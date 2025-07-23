package reports

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"time"

	"github.com/ademun/netcheck/network"
)

type Report struct {
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

func (r *Report) SaveJSON() (string, error) {
	filename := time.Now().Local().Format("2006-01-02 15-04") + ".json"

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "\t")
	encoder.Encode(r)

	return filename, nil
}

func (r *Report) SaveCSV() (string, error) {
	data := [][]string{
		{
			"Target " + r.Metadata.Target,
			"Start time " + r.Metadata.StartTime.String(),
			"End time " + r.Metadata.EndTime.String(),
			"Total time " + r.Metadata.Total,
			"Scanner " + r.Metadata.Scanner,
		},
		{
			"Port",
			"Status",
			"Banners",
		},
	}
	for _, res := range r.Results {
		data = append(data, []string{res.Port, res.Status.String(), res.Banners})
	}

	filename := time.Now().Local().Format("2006-01-02 15-04") + ".csv"

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	for _, record := range data {
		if err := writer.Write(record); err != nil {
			return "", err
		}
	}
	return filename, nil
}
