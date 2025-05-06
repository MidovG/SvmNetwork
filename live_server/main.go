package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	isMonitoring   bool
	monitoringLock sync.Mutex
	lastResults    []DetectionResult
	stats          map[string]*SessionStats
	statsMutex     sync.Mutex
)

type DetectionResult struct {
	Timestamp time.Time `json:"timestamp"`
	IsAnomaly bool      `json:"prediction"`
	Features  KDDData   `json:"features"`
}

type KDDData struct {
	Duration               float64 `json:"feature1"`
	ProtocolType           int     `json:"feature2"`
	Service                int     `json:"feature3"`
	Flag                   int     `json:"feature4"`
	SrcBytes               float64 `json:"feature5"`
	DstBytes               float64 `json:"feature6"`
	Land                   int     `json:"feature7"`
	WrongFragment          int     `json:"feature8"`
	Urgent                 int     `json:"feature9"`
	Hot                    int     `json:"feature10"`
	NumFailedLogins        int     `json:"feature11"`
	LoggedIn               int     `json:"feature12"`
	NumCompromised         int     `json:"feature13"`
	RootShell              int     `json:"feature14"`
	SuAttempted            int     `json:"feature15"`
	NumRoot                int     `json:"feature16"`
	NumFileCreations       int     `json:"feature17"`
	NumShells              int     `json:"feature18"`
	NumAccessFiles         int     `json:"feature19"`
	NumOutboundCmds        int     `json:"feature20"`
	IsHostLogin            int     `json:"feature21"`
	IsGuestLogin           int     `json:"feature22"`
	Count                  int     `json:"feature23"`
	SrvCount               int     `json:"feature24"`
	SerrorRate             float64 `json:"feature25"`
	SrvSerrorRate          float64 `json:"feature26"`
	RerrorRate             float64 `json:"feature27"`
	SrvRerrorRate          float64 `json:"feature28"`
	SameSrvRate            float64 `json:"feature29"`
	DiffSrvRate            float64 `json:"feature30"`
	SrvDiffHostRate        float64 `json:"feature31"`
	DstHostCount           int     `json:"feature32"`
	DstHostSrvCount        int     `json:"feature33"`
	DstHostSameSrvRate     float64 `json:"feature34"`
	DstHostDiffSrvRate     float64 `json:"feature35"`
	DstHostSameSrcPortRate float64 `json:"feature36"`
	DstHostSrvDiffHostRate float64 `json:"feature37"`
	DstHostSerrorRate      float64 `json:"feature38"`
	DstHostSrvSerrorRate   float64 `json:"feature39"`
	DstHostRerrorRate      float64 `json:"feature40"`
	DstHostSrvRerrorRate   float64 `json:"feature41"`
}

type SessionStats struct {
	StartTime              time.Time
	ProtocolType           int
	Service                int
	Flag                   int
	SrcBytes               float64
	DstBytes               float64
	Land                   int
	WrongFragment          int
	Urgent                 int
	Hot                    int
	NumFailedLogins        int
	LoggedIn               int
	NumCompromised         int
	RootShell              int
	SuAttempted            int
	NumRoot                int
	NumFileCreations       int
	NumShells              int
	NumAccessFiles         int
	NumOutboundCmds        int
	IsHostLogin            int
	IsGuestLogin           int
	Count                  int
	SrvCount               int
	SerrorRate             float64
	SrvSerrorRate          float64
	RerrorRate             float64
	SrvRerrorRate          float64
	SameSrvRate            float64
	DiffSrvRate            float64
	SrvDiffHostRate        float64
	DstHostCount           int
	DstHostSrvCount        int
	DstHostSameSrvRate     float64
	DstHostDiffSrvRate     float64
	DstHostSameSrcPortRate float64
	DstHostSrvDiffHostRate float64
	DstHostSerrorRate      float64
	DstHostSrvSerrorRate   float64
	DstHostRerrorRate      float64
	DstHostSrvRerrorRate   float64
}

func main() {
	stats = make(map[string]*SessionStats)

	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/start", startHandler)
	http.HandleFunc("/stop", stopHandler)
	http.HandleFunc("/results", resultsHandler)

	// Автоматическое определение интерфейса
	device := getNetworkInterface()

	//sendDeviceName(device)

	go startPacketCapture(device)

	log.Println("Server started on :8181")
	log.Fatal(http.ListenAndServe(":8181", nil))
}

func getNetworkInterface() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, device := range devices {
		for _, address := range device.Addresses {
			if ip4 := address.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
				log.Printf("Используется интерфейс: %s (%s)", device.Name, ip4)
				return device.Name
			}
		}
	}

	log.Fatal("Не найдено доступных подключений для анализа")
	return "Не найдено доступных подключений для анализа"
}

func startHandler(w http.ResponseWriter, r *http.Request) {
	monitoringLock.Lock()
	defer monitoringLock.Unlock()

	if !isMonitoring {
		isMonitoring = true
		stats = make(map[string]*SessionStats)
	}
	respondJSON(w, map[string]bool{"is_monitoring": isMonitoring})
}

func stopHandler(w http.ResponseWriter, r *http.Request) {
	monitoringLock.Lock()
	defer monitoringLock.Unlock()

	isMonitoring = false
	respondJSON(w, map[string]bool{"is_monitoring": isMonitoring})
}

func resultsHandler(w http.ResponseWriter, r *http.Request) {
	monitoringLock.Lock()
	defer monitoringLock.Unlock()

	if len(lastResults) > 10 {
		lastResults = lastResults[:10]
	}
	respondJSON(w, lastResults)
}

func startPacketCapture(device string) {
	// Проверка прав суперпользователя
	if os.Geteuid() != 0 {
		log.Fatal("You need to run this program with sudo")
	}

	handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case packet := <-packetSource.Packets():
			if !isMonitoring {
				continue
			}
			processPacket(packet)

		case <-ticker.C:
			if isMonitoring {
				statsMutex.Lock()
				for key, s := range stats {
					duration := time.Since(s.StartTime).Seconds()
					features := KDDData{
						Duration:               duration,
						ProtocolType:           s.ProtocolType,
						Service:                s.Service,
						Flag:                   s.Flag,
						SrcBytes:               s.SrcBytes,
						DstBytes:               s.DstBytes,
						Land:                   s.Land,
						WrongFragment:          s.WrongFragment,
						Urgent:                 s.Urgent,
						Hot:                    s.Hot,
						NumFailedLogins:        s.NumFailedLogins,
						LoggedIn:               s.LoggedIn,
						NumCompromised:         s.NumCompromised,
						RootShell:              s.RootShell,
						SuAttempted:            s.SuAttempted,
						NumRoot:                s.NumRoot,
						NumFileCreations:       s.NumFileCreations,
						NumShells:              s.NumShells,
						NumAccessFiles:         s.NumAccessFiles,
						NumOutboundCmds:        s.NumOutboundCmds,
						IsHostLogin:            s.IsHostLogin,
						IsGuestLogin:           s.IsGuestLogin,
						Count:                  s.Count,
						SrvCount:               s.SrvCount,
						SerrorRate:             s.SerrorRate,
						SrvSerrorRate:          s.SrvSerrorRate,
						RerrorRate:             s.RerrorRate,
						SrvRerrorRate:          s.SrvRerrorRate,
						SameSrvRate:            s.SameSrvRate,
						DiffSrvRate:            s.DiffSrvRate,
						SrvDiffHostRate:        s.SrvDiffHostRate,
						DstHostCount:           s.DstHostCount,
						DstHostSrvCount:        s.DstHostSrvCount,
						DstHostSameSrvRate:     s.DstHostSameSrvRate,
						DstHostDiffSrvRate:     s.DstHostDiffSrvRate,
						DstHostSameSrcPortRate: s.DstHostSameSrcPortRate,
						DstHostSrvDiffHostRate: s.DstHostSrvDiffHostRate,
						DstHostSerrorRate:      s.DstHostSerrorRate,
						DstHostSrvSerrorRate:   s.DstHostSrvSerrorRate,
						DstHostRerrorRate:      s.DstHostRerrorRate,
						DstHostSrvRerrorRate:   s.DstHostSrvRerrorRate,
					}
					go sendToPredictService(features)
					delete(stats, key)
				}
				statsMutex.Unlock()
			}
		}
	}
}

func processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if ipLayer == nil || (tcpLayer == nil && udpLayer == nil) {
		return
	}

	ip, _ := ipLayer.(*layers.IPv4)
	var srcPort, dstPort uint16
	protocol := 0 // 0=tcp,1=udp,2=icmp
	var flag int

	switch {
	case tcpLayer != nil:
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = uint16(tcp.SrcPort)
		dstPort = uint16(tcp.DstPort)
		protocol = 0

		// Установка TCP-флагов
		flag = 0
		if tcp.SYN {
			flag |= 0x02
		}
		if tcp.ACK {
			flag |= 0x10
		}
		if tcp.FIN {
			flag |= 0x01
		}
		if tcp.RST {
			flag |= 0x04
		}
		if tcp.PSH {
			flag |= 0x08
		}
		if tcp.URG {
			flag |= 0x20
		}
	case udpLayer != nil:
		udp, _ := udpLayer.(*layers.UDP)
		srcPort = uint16(udp.SrcPort)
		dstPort = uint16(udp.DstPort)
		protocol = 1
		flag = 0 // UDP не имеет флагов
	}

	sessionKey := fmt.Sprintf("%s:%d-%s:%d-%d",
		ip.SrcIP, srcPort, ip.DstIP, dstPort, protocol)

	statsMutex.Lock()
	defer statsMutex.Unlock()

	if stats[sessionKey] == nil {
		stats[sessionKey] = &SessionStats{
			StartTime:    time.Now(),
			ProtocolType: protocol,
			Land:         0,
			Flag:         flag,
		}

		// Проверка условия Land (одинаковые IP и порты)
		if ip.SrcIP.Equal(ip.DstIP) && srcPort == dstPort {
			stats[sessionKey].Land = 1
		}
	}

	stats[sessionKey].Count++
	stats[sessionKey].SrcBytes += float64(len(packet.Data()))

	if isResponse(ip.DstIP) {
		stats[sessionKey].DstBytes += float64(len(packet.Data()))
		stats[sessionKey].DstHostCount++
	}
}

func isResponse(ip []byte) bool {
	return ip[0] == 192 && ip[1] == 168
}

func sendToPredictService(features KDDData) {
	body, _ := json.Marshal(features)
	resp, err := http.Post(
		"http://127.0.0.1:5000/predict",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		log.Printf("Error sending to Python: %v", err)
		return
	}
	defer resp.Body.Close()

	var result struct{ IsAnomaly bool }
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Printf("Error decoding response: %v", err)
		return
	}

	monitoringLock.Lock()
	defer monitoringLock.Unlock()
	lastResults = append([]DetectionResult{{
		Timestamp: time.Now(),
		IsAnomaly: result.IsAnomaly,
		Features:  features,
	}}, lastResults...)
}

func respondJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
