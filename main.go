package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/gosnmp/gosnmp"
	"github.com/olekukonko/tablewriter"
)

type SNMPv3Client struct {
	client *gosnmp.GoSNMP
}

type SNMPv3Config struct {
	Target        string
	Port          int
	Username      string
	AuthProtocol  string // "SHA" or "MD5"
	AuthPassword  string
	PrivProtocol  string // "AES" or "DES"
	PrivPassword  string
	TimeoutSecs   int
	Transport     string // "udp" or "tcp"
	SecurityLevel string
}

type SNMPResult struct {
	IP           string
	Username     string
	Password     string
	EncPassword  string
	AuthProtocol string
	PrivProtocol string
	Success      bool
	Message      string
	Command      string
}

// NewSNMPv3EnumClient - specifically for engine enumeration
func NewSNMPv3EnumClient(config *SNMPv3Config) (*SNMPv3Client, error) {
	client := &gosnmp.GoSNMP{
		Target:        config.Target,
		Port:          uint16(config.Port),
		Version:       gosnmp.Version3,
		Timeout:       time.Duration(config.TimeoutSecs) * time.Second,
		Retries:       1,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.NoAuthNoPriv,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName: config.Username,
		},
		Transport: config.Transport,
	}

	err := client.Connect()
	if err != nil {
		return nil, err
	}

	// Trigger discovery with Get request, ignore errors
	oids := []string{"1.3.6.1.2.1.1.1.0"}
	_, _ = client.Get(oids)

	return &SNMPv3Client{client: client}, nil
}

// NewSNMPv3AuthClient - for user enumeration and brute force
func NewSNMPv3AuthClient(config *SNMPv3Config) (*SNMPv3Client, error) {
	var msgFlags gosnmp.SnmpV3MsgFlags
	switch strings.ToLower(config.SecurityLevel) {
	case "authpriv":
		msgFlags = gosnmp.AuthPriv
	case "authnopriv":
		msgFlags = gosnmp.AuthNoPriv
	default:
		msgFlags = gosnmp.NoAuthNoPriv
	}

	client := &gosnmp.GoSNMP{
		Target:        config.Target,
		Port:          uint16(config.Port),
		Version:       gosnmp.Version3,
		Timeout:       time.Duration(config.TimeoutSecs) * time.Second,
		Retries:       1,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      msgFlags,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 config.Username,
			AuthenticationProtocol:   getAuthProtocol(config.AuthProtocol),
			AuthenticationPassphrase: config.AuthPassword,
			PrivacyProtocol:          getPrivProtocol(config.PrivProtocol),
			PrivacyPassphrase:        config.PrivPassword,
		},
		Transport: config.Transport,
	}

	err := client.Connect()
	if err != nil {
		return nil, err
	}
	return &SNMPv3Client{client: client}, err
}

func (c *SNMPv3Client) Get(oids []string, showDetails bool) (map[string]interface{}, error) {
	result, err := c.client.Get(oids)
	if err != nil {
		return nil, err
	}

	values := make(map[string]interface{})
	for _, variable := range result.Variables {
		values[variable.Name] = gosnmp.ToBigInt(variable.Value)
	}

	return values, nil
}

func (c *SNMPv3Client) Close() error {
	return c.client.Conn.Close()
}

func getAuthProtocol(protocol string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(protocol) {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA224":
		return gosnmp.SHA224
	case "SHA256":
		return gosnmp.SHA256
	case "SHA384":
		return gosnmp.SHA384
	case "SHA512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

func getPrivProtocol(protocol string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(protocol) {
	case "AES":
		return gosnmp.AES
	case "DES":
		return gosnmp.DES
	default:
		return gosnmp.NoPriv
	}
}

func parseEngineID(engineID []byte) {
	if len(engineID) < 6 {
		fmt.Println("Engine ID too short to parse")
		return
	}

	format := engineID[0] >> 4
	enterpriseID := int32(engineID[0]&0x0F)<<24 | int32(engineID[1])<<16 | int32(engineID[2])<<8 | int32(engineID[3])

	enterpriseMap := loadEnterpriseIDs()
	enterpriseName := enterpriseMap[enterpriseID]
	if enterpriseName == "" {
		enterpriseName = "Unknown"
	}

	macBytes := engineID[5:]
	if len(macBytes) < 6 {
		fmt.Println("Not enough bytes for MAC address")
		return
	}
	macAddress := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		macBytes[0], macBytes[1], macBytes[2],
		macBytes[3], macBytes[4], macBytes[5])

	fmt.Printf("Engine ID Format: %d\n", format)
	fmt.Printf("Enterprise ID: %s (%d)\n", enterpriseName, enterpriseID)
	fmt.Printf("MAC Address: %s\n", macAddress)
}

func loadEnterpriseIDs() map[int32]string {
	content, err := os.ReadFile("enterpriseIDs.txt")
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return make(map[int32]string)
	}

	lines := strings.Split(string(content), "\n")
	idMap := make(map[int32]string)

	for i := 0; i < len(lines)-1; i++ {
		if id, err := strconv.ParseInt(strings.TrimSpace(lines[i]), 10, 32); err == nil {
			if i+1 < len(lines) {
				idMap[int32(id)] = strings.TrimSpace(lines[i+1])
			}
		}
	}

	return idMap
}

func getIPList(ipList, ipFile string) []string {
	var ips []string
	if ipList != "" {
		// Handle comma-separated IPs
		for _, ip := range strings.Split(ipList, ",") {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				ips = append(ips, ip)
			}
		}
	} else if ipFile != "" {
		uniqueIPs, err := uniqueLines(ipFile)
		if err != nil {
			log.Fatalf("Failed to read IP file: %v", err)
		}
		ips = uniqueIPs
	}
	return ips
}

func getResultMessage(err error) string {
	if err == nil {
		return "SNMP service detected"
	}
	return fmt.Sprintf("Error: %v", err)
}

func performEnumeration(ips []string, protocol string, port int) []SNMPResult {
	results := []SNMPResult{}
	config := &SNMPv3Config{
		Port:          port,
		Username:      "myuser",
		AuthProtocol:  "SHA",
		AuthPassword:  "authpass",
		PrivProtocol:  "AES",
		PrivPassword:  "privpass",
		TimeoutSecs:   2,
		Transport:     protocol,
		SecurityLevel: "noAuthNoPriv",
	}

	for _, ip := range ips {
		fmt.Printf("\n=== Testing IP: %s ===\n", ip)
		config.Target = ip
		client, err := NewSNMPv3EnumClient(config)
		if err != nil {
			results = append(results, SNMPResult{
				IP:      ip,
				Success: false,
				Message: err.Error(),
			})
			continue
		}
		defer client.Close()

		if params, ok := client.client.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
			fmt.Printf("\nSNMP Engine Details:\n")
			fmt.Printf("Authorization Engine ID (hex): %x\n", params.AuthoritativeEngineID)
			fmt.Printf("Authorization Engine Boots: %d\n", params.AuthoritativeEngineBoots)
			fmt.Printf("Authorization Engine Time: %d\n", params.AuthoritativeEngineTime)

			fmt.Printf("\nParsed Authorization Engine ID:\n")
			engineID := []byte(params.AuthoritativeEngineID)
			parseEngineID(engineID)
		}

		oids := []string{"1.3.6.1.2.1.1.1.0"}
		_, err = client.Get(oids, true)
		results = append(results, SNMPResult{
			IP:      ip,
			Success: err == nil,
			Message: getResultMessage(err),
		})
	}
	return results
}

func displayEnumResults(results []SNMPResult) {
	for _, result := range results {
		if result.Success {
			fmt.Printf("[+] %s: %s\n", result.IP, result.Message)
		} else if !strings.Contains(result.Message, "unknown username") {
			// Only display errors that are not "unknown username"
			fmt.Printf("[-] %s: %s\n", result.IP, result.Message)
		}
	}
}

func main() {
	ipList := flag.String("ips", "", "Comma-separated list of IPs to check")
	ipFile := flag.String("ipfile", "", "File containing list of IPs to check, one per line")
	userFile := flag.String("userfile", "", "File containing usernames to test")
	passFile := flag.String("passfile", "", "Password list for brute force")
	encFile := flag.String("encfile", "", "File containing encryption passwords")
	enumFlag := flag.Bool("enum", false, "Perform basic SNMP enumeration")
	bruteFlag := flag.Bool("brute", false, "Perform password brute force")
	userEnumFlag := flag.Bool("userenum", false, "Perform username enumeration")
	protocol := flag.String("protocol", "udp", "SNMP protocol to use (udp or tcp)")
	workers := flag.Int("workers", 10, "Number of workers for brute force")
	port := flag.Int("port", 161, "SNMP port number")
	flag.Parse()

	// Print warning message
	color.Red("\nWARNING: Please note that the very nature of identification of some of these issues can be unreliable.")
	color.Red("Manual validation is always required.\n")

	if !*enumFlag && !*bruteFlag && !*userEnumFlag {
		log.Fatal("Must specify either --enum, --userenum, or --brute flag")
	}

	if *enumFlag {
		results := performEnumeration(getIPList(*ipList, *ipFile), *protocol, *port)
		displayEnumResults(results)
	} else if *userEnumFlag {
		if *userFile == "" {
			log.Fatal("Username enumeration requires --userfile")
		}
		results := performUserEnum(getIPList(*ipList, *ipFile), *userFile, *protocol, *port, *workers)
		displayUserEnumResults(results)
		saveUserResults(results)
	} else if *bruteFlag {
		if *userFile == "" || *passFile == "" {
			log.Fatal("Brute force requires --userfile and --passfile")
		}

		// First check if userFile contains IP:username combos
		content, err := os.ReadFile(*userFile)
		if err != nil {
			log.Fatalf("Failed to read user file: %v", err)
		}
		hasIPUserCombos := strings.Contains(string(content), ":")

		// Only check for IPs if we don't have combos
		if !hasIPUserCombos {
			ips := getIPList(*ipList, *ipFile)
			if len(ips) == 0 {
				log.Fatal("When using a file with usernames only, you must specify target IPs with -ips or -ipfile")
			}
		}

		results := performBruteForce(*userFile, *passFile, *encFile, *ipList, *ipFile, *protocol, *workers, *port)
		displayBruteResults(results)
	}
}

func performUserEnum(ips []string, userFile string, protocol string, port int, workers int) []SNMPResult {
	results := []SNMPResult{}
	var resultsMutex sync.Mutex

	// We only need to load standalone usernames here
	usernames, err := loadUsernames(userFile)
	if err != nil {
		log.Fatalf("Failed to load usernames: %v", err)
	}

	// Filter out usernames longer than 32 characters
	var validUsernames []string
	for _, username := range usernames {
		if len(username) <= 32 {
			validUsernames = append(validUsernames, username)
		} else {
			fmt.Printf("[!] Skipping username '%s' - exceeds 32 character limit\n", username)
		}
	}
	usernames = validUsernames

	// Create a channel for work items (username + progress)
	type workItem struct {
		username string
		current  int
	}
	workChan := make(chan workItem)
	var wg sync.WaitGroup

	totalTests := len(usernames)
	fmt.Printf("[*] Starting user enumeration with %d workers\n", workers)
	fmt.Printf("[*] Testing %d usernames against %d IPs\n", len(usernames), len(ips))

	// Start worker pool
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			config := &SNMPv3Config{
				Port:         port,
				AuthPassword: "authpass",
				PrivProtocol: "AES",
				PrivPassword: "privpass",
				TimeoutSecs:  5,
				Transport:    protocol,
			}

			for work := range workChan {
				username := work.username
				for _, ip := range ips {
					config.Target = ip
					config.Username = username
					userFound := false

					// Try both SHA and MD5
					for _, authProto := range []string{"SHA", "MD5"} {
						if userFound {
							break
						}

						config.AuthProtocol = authProto
						client, err := NewSNMPv3AuthClient(config)

						if err == nil {
							oids := []string{"1.3.6.1.2.1.1.1.0"}
							_, err = client.Get(oids, false)

							if err == nil {
								userFound = true
								resultsMutex.Lock()
								results = append(results, SNMPResult{
									IP:           ip,
									Username:     username,
									AuthProtocol: authProto,
									Success:      true,
								})
								resultsMutex.Unlock()
								color.Green("[+] Valid username found on %s: %s", ip, username)
							} else {
								errStr := err.Error()
								if strings.Contains(errStr, "authentication failure") ||
									strings.Contains(errStr, "authorization error") ||
									strings.Contains(errStr, "wrong digest") ||
									(protocol == "tcp" && strings.Contains(errStr, "request timeout")) {
									userFound = true
									resultsMutex.Lock()
									results = append(results, SNMPResult{
										IP:           ip,
										Username:     username,
										AuthProtocol: authProto,
										Success:      true,
									})
									resultsMutex.Unlock()
									color.Green("[+] Valid username found on %s: %s (Authentication failure)", ip, username)
								} else if strings.Contains(errStr, "unknown username") && !userFound {
									fmt.Printf("[-] Testing username %s on %s (%d/%d): %s\n", username, ip, work.current, totalTests, errStr)
								}
							}
							client.Close()
						}
					}

					if !userFound {
						// Remove this line to avoid duplicate error messages
						// fmt.Printf("[-] Testing username %s on %s (%d/%d): Invalid user\n",
						// 	username, ip, work.current, totalTests)
					}
				}
			}
		}()
	}

	// Send usernames to workers
	for i, username := range usernames {
		workChan <- workItem{username: username, current: i + 1}
	}
	close(workChan)
	wg.Wait()

	return results
}

func loadUsernames(filename string) ([]string, error) {
	return uniqueLines(filename)
}

func saveUserResults(results []SNMPResult) {
	if len(results) == 0 {
		return
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("foundusers_%s.txt", timestamp)

	var content strings.Builder
	for _, result := range results {
		content.WriteString(fmt.Sprintf("%s:%s\n", result.IP, result.Username))
	}

	err := os.WriteFile(filename, []byte(content.String()), 0644)
	if err != nil {
		fmt.Printf("Error saving results to file: %v\n", err)
		return
	}

	fmt.Printf("\nValid usernames saved to: %s\n", filename)
}

func uniqueLines(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Create a map to store unique lines
	uniqueMap := make(map[string]bool)

	// Split content into lines and add to map
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	for _, line := range lines {
		// Trim whitespace and skip empty lines
		line = strings.TrimSpace(line)
		if line != "" {
			uniqueMap[line] = true
		}
	}

	// Convert map keys back to slice
	var uniqueLines []string
	for line := range uniqueMap {
		uniqueLines = append(uniqueLines, line)
	}

	return uniqueLines, nil
}

func loadUserCombos(filename, ipList, ipFile string) ([]string, error) {
	var combos []string
	uniqueMap := make(map[string]bool)

	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var usernames []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, ":") {
			uniqueMap[line] = true // If line contains IP:username format, add directly
		} else {
			usernames = append(usernames, line) // Otherwise store as username only
		}
	}

	// This part might be inefficient - it tries every username against every IP
	ips := getIPList(ipList, ipFile)
	if len(ips) > 0 {
		for _, ip := range ips {
			for _, username := range usernames {
				combo := fmt.Sprintf("%s:%s", ip, username)
				uniqueMap[combo] = true
			}
		}
	}

	for combo := range uniqueMap {
		combos = append(combos, combo)
	}

	return combos, nil
}

func performBruteForce(userFile, passFile, encFile, ipList, ipFile, protocol string, maxWorkers, port int) []SNMPResult {
	results := []SNMPResult{}
	var resultsMutex sync.Mutex
	foundUsers := make(map[string]bool)

	userCombos, err := loadUserCombos(userFile, ipList, ipFile)
	if err != nil {
		log.Fatalf("Failed to load user combinations: %v", err)
	}

	passwords, err := uniqueLines(passFile)
	if err != nil {
		log.Fatalf("Failed to load passwords: %v", err)
	}

	var encPasswords []string
	if encFile != "" {
		encPasswords, err = uniqueLines(encFile)
		if err != nil {
			log.Fatalf("Failed to load encryption passwords: %v", err)
		}
	} else {
		encPasswords = passwords
	}

	// Split auth protocols into basic and advanced
	basicAuthProtos := []string{"MD5", "SHA"}
	advancedAuthProtos := []string{"SHA256", "SHA384", "SHA512", "SHA224"}
	privProtos := []string{"AES", "DES"}

	nullAuthCombos := int32(len(userCombos))
	authNoPrivCombos := int32(len(userCombos) * len(passwords) * len(basicAuthProtos))
	authPrivCombos := int32(len(userCombos) * len(passwords) * len(encPasswords) * len(basicAuthProtos) * len(privProtos))

	totalCombos := nullAuthCombos + authNoPrivCombos + authPrivCombos

	fmt.Printf("[*] Starting brute force with %d workers\n", maxWorkers)
	fmt.Printf("[*] Total combinations to test: %d\n", totalCombos)
	fmt.Printf("[*] Combinations breakdown:\n")
	fmt.Printf("    - NULL Auth: %d (users:%d)\n",
		nullAuthCombos, len(userCombos))
	fmt.Printf("    - AuthNoPriv: %d (users:%d × passwords:%d × auth_protocols:%d)\n",
		authNoPrivCombos, len(userCombos), len(passwords), len(basicAuthProtos))
	fmt.Printf("    - AuthPriv: %d (users:%d × passwords:%d × enc_passwords:%d × auth_protocols:%d × priv_protocols:%d)\n",
		authPrivCombos, len(userCombos), len(passwords), len(encPasswords), len(basicAuthProtos), len(privProtos))
	fmt.Printf("    - Total combinations: %d\n", totalCombos)

	var progress int32
	workChan := make(chan struct{ ip, username string })
	var wg sync.WaitGroup

	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for combo := range workChan {
				resultsMutex.Lock()
				if foundUsers[combo.username] {
					resultsMutex.Unlock()
					continue
				}
				resultsMutex.Unlock()

				// Try NULL auth first
				currentProgress := atomic.AddInt32(&progress, 1)
				if result := tryNullAuth(combo.ip, combo.username, protocol, currentProgress, totalCombos, port); result != nil {
					resultsMutex.Lock()
					results = append(results, *result)
					foundUsers[combo.username] = true
					resultsMutex.Unlock()
					continue
				}

				// Try basic AuthNoPriv (MD5/SHA) first
				userFound := false
				for _, authProto := range basicAuthProtos {
					if userFound {
						break
					}
					for _, pass := range passwords {
						currentProgress = atomic.AddInt32(&progress, 1)
						if result := tryAuthNoPriv(combo.ip, combo.username, pass, authProto, protocol, currentProgress, totalCombos, port); result != nil {
							resultsMutex.Lock()
							results = append(results, *result)
							foundUsers[combo.username] = true
							resultsMutex.Unlock()
							userFound = true
							break
						}
					}
				}
				if userFound {
					continue
				}

				// Try advanced AuthNoPriv if basic fails
				for _, authProto := range advancedAuthProtos {
					if userFound {
						break
					}
					for _, pass := range passwords {
						currentProgress = atomic.AddInt32(&progress, 1)
						if result := tryAuthNoPriv(combo.ip, combo.username, pass, authProto, protocol, currentProgress, totalCombos, port); result != nil {
							resultsMutex.Lock()
							results = append(results, *result)
							foundUsers[combo.username] = true
							resultsMutex.Unlock()
							userFound = true
							break
						}
					}
				}
				if userFound {
					continue
				}

				// Try AuthPriv only if everything else fails
				for _, authProto := range basicAuthProtos {
					if userFound {
						break
					}
					for _, pass := range passwords {
						for _, privProto := range privProtos {
							for _, privPass := range encPasswords {
								currentProgress = atomic.AddInt32(&progress, 1)
								if result := tryAuthPriv(combo.ip, combo.username, pass, privPass, authProto, privProto, protocol, currentProgress, totalCombos, port); result != nil {
									resultsMutex.Lock()
									results = append(results, *result)
									foundUsers[combo.username] = true
									resultsMutex.Unlock()
									userFound = true
									break
								}
							}
							if userFound {
								break
							}
						}
						if userFound {
							break
						}
					}
				}
			}
		}()
	}

	for _, combo := range userCombos {
		parts := strings.Split(combo, ":")
		if len(parts) != 2 {
			continue
		}
		ip, username := parts[0], parts[1]
		workChan <- struct{ ip, username string }{ip, username}
	}

	close(workChan)
	wg.Wait()

	return results
}

func displayBruteResults(results []SNMPResult) {
	if len(results) == 0 {
		fmt.Println("\nNo valid credentials found.")
		return
	}

	fmt.Println("\nValid Users:")
	fmt.Println("==================")

	// Create and configure table
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Host", "Username", "Auth Type", "Auth Protocol", "Auth Password", "Priv Protocol", "Priv Password", "Command"})
	table.SetBorders(tablewriter.Border{Left: true, Top: true, Right: true, Bottom: true})
	table.SetCenterSeparator("|")
	table.SetAutoWrapText(false)
	table.SetRowLine(true)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiYellowColor},
	)

	for _, result := range results {
		authType := "NULL"
		authProto := "-"
		authPass := "-"
		privProto := "-"
		privPass := "-"

		if result.AuthProtocol != "" {
			if result.PrivProtocol != "" {
				authType = "authPriv"
				privProto = result.PrivProtocol
				privPass = result.EncPassword
			} else {
				authType = "authNoPriv"
			}
			authProto = result.AuthProtocol
			authPass = result.Password
		}

		table.Append([]string{
			result.IP,
			result.Username,
			authType,
			authProto,
			authPass,
			privProto,
			privPass,
			result.Command,
		})
	}

	table.Render()
}

func tryNullAuth(ip, username, protocol string, current, total int32, port int) *SNMPResult {
	fmt.Printf("[*] [NULL Auth] Testing %s@%s (%d/%d)\n", username, ip, current, total)
	config := &SNMPv3Config{
		Target:      ip,
		Port:        port,
		Username:    username,
		Transport:   protocol,
		TimeoutSecs: 2,
	}

	client, err := NewSNMPv3AuthClient(config)
	if err != nil {
		return nil
	}
	defer client.Close()

	oids := []string{"1.3.6.1.2.1.1.1.0"}
	result, err := client.client.Get(oids) // Get raw result to check variables

	// Check if we actually got data back
	if err == nil && result != nil && len(result.Variables) > 0 && result.Variables[0].Value != nil {
		color.Green("[+] [NULL Auth] SUCCESS: %s@%s", username, ip)
		walkCmd := fmt.Sprintf("snmpwalk -v3 -l noAuthNoPriv -u %s %s", username, ip)
		return &SNMPResult{
			IP:       ip,
			Username: username,
			Success:  true,
			Command:  walkCmd,
			Message:  "NULL auth",
		}
	}
	return nil
}

func tryAuthNoPriv(ip, username, password, authProto, protocol string, current, total int32, port int) *SNMPResult {
	fmt.Printf("[*] [AuthNoPriv] Testing %s@%s (Auth Protocol:%s Priv Protocol:NONE Auth Password:%s) (%d/%d)\n",
		username, ip, authProto, password, current, total)
	config := &SNMPv3Config{
		Target:        ip,
		Port:          port,
		Username:      username,
		AuthProtocol:  authProto,
		AuthPassword:  password,
		Transport:     protocol,
		TimeoutSecs:   2,
		SecurityLevel: "authNoPriv",
	}

	client, err := NewSNMPv3AuthClient(config)
	if err != nil {
		return nil
	}
	defer client.Close()

	oids := []string{"1.3.6.1.2.1.1.1.0"}
	_, err = client.Get(oids, false)
	if err != nil {
		return nil
	}

	color.Green("[+] [AuthNoPriv] SUCCESS: %s@%s (Auth Protocol:%s Auth Password:%s)",
		username, ip, authProto, password)
	walkCmd := fmt.Sprintf("snmpwalk -v3 -l authNoPriv -u %s -a %s -A %s %s",
		username, authProto, password, ip)
	return &SNMPResult{
		IP:           ip,
		Username:     username,
		Password:     password,
		AuthProtocol: authProto,
		Success:      true,
		Command:      walkCmd,
		Message:      fmt.Sprintf("Auth: %s", authProto),
	}
}

func tryAuthPriv(ip, username, authPass, privPass, authProto, privProto, protocol string, current, total int32, port int) *SNMPResult {
	fmt.Printf("[*] [AuthPriv] Testing %s@%s (Auth Protocol:%s Priv Protocol:%s Auth Password:%s Priv Password:%s) (%d/%d)\n",
		username, ip, authProto, privProto, authPass, privPass, current, total)
	config := &SNMPv3Config{
		Target:        ip,
		Port:          port,
		Username:      username,
		AuthProtocol:  authProto,
		AuthPassword:  authPass,
		PrivProtocol:  privProto,
		PrivPassword:  privPass,
		Transport:     protocol,
		TimeoutSecs:   2,
		SecurityLevel: "authPriv",
	}

	client, err := NewSNMPv3AuthClient(config)
	if err != nil {
		return nil
	}
	defer client.Close()

	oids := []string{"1.3.6.1.2.1.1.1.0"}
	_, err = client.Get(oids, false)
	if err != nil {
		return nil
	}

	color.Green("[+] [AuthPriv] SUCCESS: %s@%s (Protocols:%s/%s Auth:%s Priv:%s)",
		username, ip, authProto, privProto, authPass, privPass)
	walkCmd := fmt.Sprintf("snmpwalk -v3 -l authPriv -u %s -a %s -A %s -x %s -X %s %s",
		username, authProto, authPass, privProto, privPass, ip)
	return &SNMPResult{
		IP:           ip,
		Username:     username,
		Password:     authPass,
		EncPassword:  privPass,
		AuthProtocol: authProto,
		PrivProtocol: privProto,
		Success:      true,
		Command:      walkCmd,
		Message:      fmt.Sprintf("Auth: %s, Priv: %s", authProto, privProto),
	}
}

func displayUserEnumResults(results []SNMPResult) {
	if len(results) > 0 {
		fmt.Println("\nValid Usernames Found:")
		fmt.Println("==================")
		fmt.Println("|-----------------|----------|")
		fmt.Println("|      HOST       | USERNAME |")
		fmt.Println("|-----------------|----------|")
		for _, result := range results {
			fmt.Printf("| %-15s | %-8s |\n", result.IP, result.Username)
		}
		fmt.Println("|-----------------|----------|")
		fmt.Println("\nTo manually test these usernames, try:")
		fmt.Println("UDP:")
		fmt.Println("snmpwalk -v3 -l authNoPriv -u <username> -a MD5 -A password <ip>")
		fmt.Println("or")
		fmt.Println("snmpwalk -v3 -l authNoPriv -u <username> -a SHA -A password <ip>")
		fmt.Println("\nTCP:")
		fmt.Println("snmpwalk -v3 -l authNoPriv -u <username> -a MD5 -A password -t 2 -r 2 tcp:<ip>:161")
		fmt.Println("or")
		fmt.Println("snmpwalk -v3 -l authNoPriv -u <username> -a SHA -A password -t 2 -r 2 tcp:<ip>:161")
	} else {
		fmt.Println("\nNo valid usernames found.")
	}
}
