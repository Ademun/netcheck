package reports

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ademun/netcheck/network"
)

type JSONReport struct {
	Metadata *Metadata
	Results  []network.Result
}

type Metadata struct {
	Target    string
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Total     string
	Scanner   string
}

func (jr *JSONReport) Save() error {
	data, err := json.MarshalIndent(jr, "", "\t")
	if err != nil {
		return err
	}
	filename := time.Now().Local().Format("2006-01-02 15-04") + ".json"
	fmt.Println(filename)
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return err
	}
	return nil
}
