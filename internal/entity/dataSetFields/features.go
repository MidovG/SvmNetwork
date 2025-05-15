package dataSetFields

import "time"

// Структура, соответствующая таблице
type Record struct {
	ID                     int
	TimestampStr           string
	Timestamp              time.Time
	IsAnomaly              bool
	Duration               float64
	ProtocolType           string
	Service                string
	Flag                   string
	SrcBytes               int
	DstBytes               int
	Land                   bool
	WrongFragment          int
	Urgent                 int
	Hot                    int
	NumFailedLogins        int
	LoggedIn               bool
	NumCompromised         int
	RootShell              bool
	SuAttempted            bool
	NumRoot                int
	NumFileCreations       int
	NumShells              int
	NumAccessFiles         int
	NumOutboundCmds        int
	IsHostLogin            bool
	IsGuestLogin           bool
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
	UserID                 int
	CreatedAtStr           string
	CreatedAt              time.Time
}
