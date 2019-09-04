/*
OpenIO SDS oio-mover-client
Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
Description: This standalone tool can be used to interact with the oio-admin-agent
    Long term, it can be merged into the openio-admin CLI
Dependencies:
   - go (1.10+ tested)
   - go get github.com/olekukonko/tablewriter
Build:
   - go build -ldflags="-X main.version=[VERSION]" bin/oio-mover-client.go
Limitations:
   - This can't be used to run blob_rebuild jobs
*/

package main

import(
    "net/http"
    "flag"
    "io/ioutil"
    "log"
    "encoding/json"
    "os"
    "strings"
    "errors"
    "bytes"
    "time"
    "fmt"
    "path"
    "bufio"
    "github.com/olekukonko/tablewriter"
)

type job struct {
    ID string `json:"id"`
    Host string `json:"host"`
    Config map[string]interface{} `json:"config"`
    Stats map[string]int `json:"stats"`
    Start int64 `json:"start"`
    Status int64 `json:"status"`
    End int64 `json:"end"`
    Service string `json:"service"`
    Type string `json:"type"`
    Volume string `json:"volume"`
}

type serviceInfo []struct {
	Addr  string
	Score int
	Local bool
    Tags tags
    Vol string
    Type string
}

type tags struct {
    Loc string `json:"tag.loc"`
    Vol string `json:"tag.vol"`
}

type service struct{
    Addr string
    Location string
    Volume string
    Type string
}

var httpClient *http.Client

var version string

func httpGet(url string) (string, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return "", err
	}
    if strings.HasPrefix(resp.Status, "4") || strings.HasPrefix(resp.Status, "5") {
        return "", fmt.Errorf("Invalid status code %s: %s", url, resp.Status)
    }
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func httpPost(url string, data map[string]interface{}) (string, error) {
    jsonValue, _ := json.Marshal(data)
    resp, err := httpClient.Post(url, "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func httpDelete(url string) (error) {
    req, err := http.NewRequest("DELETE", url, nil)
    if err != nil {
        return err
    }
    resp, err := httpClient.Do(req)
    if err != nil {
        return err
    }
    if strings.HasPrefix(resp.Status, "4") || strings.HasPrefix(resp.Status, "5") {
        return fmt.Errorf("Invalid status code %s: %s", url, resp.Status)
    }
    return nil
}

func main() {
    var ns string
    var host string
    var vol string
    var svc string
    var exclude string
    var minsize int64
    var maxsize int64
    var cps int64
    var bps int64
    var concurrency int64
    var target int64
    var timeout int64
    var serviceType string
    var endpoint string
    var action string
    var showVersion bool
    var defaultNS = "OPENIO"
    var availActions = map[string]string{
        "start": "Run a new mover job",
        "status": "Retrieve status of mover jobs",
        "stop": "Stop a job (cleanly)",
    }

    // Common
    fs := flag.NewFlagSet("", flag.ExitOnError)
    fs.Usage = func() {
        fmt.Fprintf(os.Stderr, "Usage %s [action] (opts)\n* Actions:\n", os.Args[0])
        for a, desc := range(availActions) {
            fmt.Fprintf(os.Stderr, "   %s\n        %s\n", a, desc)
        }
        fmt.Fprintf(os.Stderr, "* Options:\n")
        fs.PrintDefaults()
    }

    fs.StringVar(&ns, "ns", defaultNS, "Namespace")
    fs.StringVar(&endpoint, "endpoint", "", "Force oioproxy endpoint")
    fs.StringVar(&svc, "svc", "", "Target service")
    fs.StringVar(&vol, "vol", "", "Target volume")
    fs.StringVar(&host, "host", "", "Target host")
    fs.Int64Var(&timeout, "timeout", 3, "Proxy timeout")

    // Start
    fs.StringVar(&exclude, "exclude", "", "Comma separated targets to exclude (rawx only)")
    fs.Int64Var(&minsize, "minsize", 0, "Min size for bases/chunks")
    fs.Int64Var(&maxsize, "maxsize", 0, "Max size for bases/chunks")
    fs.Int64Var(&cps, "cps", 0, "Chunk throttling (rawx only)")
    fs.Int64Var(&bps, "bps", 0, "Byte throttling (rawx only)")
    fs.Int64Var(&target, "target", 0, "Target usage (rawx only)")
    fs.Int64Var(&concurrency, "concurrency", 0, "Worker concurrency (rawx only)")
    fs.BoolVar(&showVersion, "version", false, "Print version and exit")

    // Status
    fs.StringVar(&serviceType, "type", "", "Service type (status only)")

    if len(os.Args) > 0 {
        if _, ok := availActions[os.Args[1]]; ok {
            action = os.Args[1]
            fs.Parse(os.Args[2:])
        }
    }
    if action == "" {
        fs.Parse(os.Args[1:])
    }

    if showVersion {
        if version == "" {
            version = "unknown"
        }
        fmt.Printf("%s\n", version)
        return
    }

    if ns == defaultNS && os.Getenv("OIO_NS") != "" {
        ns = os.Getenv("OIO_NS")
    }

    if endpoint == "" {
        var err error
        endpoint, err = proxyAddr("/etc/oio/sds.conf.d/", ns)
        if err != nil {
            log.Fatal("Error in determining endpoint", err)
        }
    }

    httpClient = &http.Client{
        Timeout: time.Second * time.Duration(timeout),
    }

    switch action {
        case "start":
            svcObj, _ := resolveService(endpoint, ns, svc, host, vol)
            moverAgentAddr, err := resolveMoverAgent(endpoint, ns, svcObj.Location)
            if err != nil {
                log.Fatalln("Error in resolving mover agent", err)
            }
            opts := map[string]interface{}{"type": svcObj.Type, "src": svcObj.Addr}

            if (minsize > 0) {
                opts["minsize"] = minsize
            }
            if (maxsize > 0) {
                opts["maxsize"] = maxsize
            }

            if svcObj.Type == "rawx" {
                if concurrency > 0 {
                    opts["concurrency"] = concurrency
                }
                if bps > 0 {
                    opts["bps"] = bps
                }
                if cps > 0 {
                    opts["cps"] = cps
                }
                if target > 0 {
                    opts["target"] = target
                }
                if exclude != "" {
                    opts["exclude"] = strings.Split(exclude, ",")
                }
            }
            res, err := httpPost("http://" + moverAgentAddr + "/api/v1/jobs", opts)
            if err != nil {
                log.Fatal(err)
            }
            log.Println(res)
        case "stop":
            var jobID string
            svcObj, _ := resolveService(endpoint, ns, svc, host, vol)
            moverAgentAddr, err := resolveMoverAgent(endpoint, ns, svcObj.Location)
            if err != nil {
                log.Fatalln("Error in resolving mover agent", err)
            }

            jobs, err := listJobs(moverAgentAddr)
            if err != nil {
                log.Fatal(err)
            }

            for _, job := range(jobs) {
                if svcObj.Addr == job.Service && job.Status == 0 {
                    jobID = job.ID
                    break
                }
            }
            if jobID == "" {
                log.Fatalf("Could not find running job on host %s with volume %s", host, vol)
            }
            err = httpDelete("http://" + moverAgentAddr + "/api/v1/jobs/" + jobID)
            if err != nil {
                log.Fatal(err)
            }
        case "status":
            scList, _ := services(endpoint, ns, "mover-agent")

            data := [][]string{}
            for _, s := range(scList) {
                jobs, err := listJobs(s.Addr)
                if err != nil {
                    log.Fatal(err)
                }

                for _, job := range(jobs) {
                    start := time.Unix(job.Start, 0).UTC().Format("2006-01-02T15:04:05")
                    duration := "N/A"
                    if (job.End > 0) {
                        duration = time.Unix(job.End, 0).Sub(time.Unix(job.Start, 0)).String()
                    }
                    if (svc != "" && job.Service != svc) {
                        continue
                    }
                    if (host != "" && job.Host != host) {
                        continue
                    }
                    if (vol != "" && job.Volume != vol) {
                        continue
                    }
                    if (serviceType != "" && job.Type != serviceType) {
                        continue
                    }

                    stats := fmt.Sprintf("%d / %d / %d", job.Stats["success"], job.Stats["failed"], job.Stats["total"])
                    data = append(data, []string{
                            job.Host,
                            job.Type,
                            job.Service,
                            job.Volume,
                            start,
                            duration,
                            parseStatus(job.Status),
                            stats,
                    })
                }
            }
            if len(data) > 0 {
                table := tablewriter.NewWriter(os.Stdout)
                table.SetHeader([]string{"Host", "Type", "Service", "Volume", "Started", "Took", "Status", "OK/FAIL/TOT"})
                for _, v := range data {
                    table.Append(v)
                }
                table.Render()
            } else {
                fmt.Println("No jobs found")
            }
        default:
            // TODO: Use availActions here
            log.Fatalln("Invalid action " + action + ", must be in (start|status|stop)")
    }
}

func parseStatus(status int64) (string) {
    switch status {
        case 0:
            return "running"
        case 1:
            return "stopped"
        case 2:
            return "completed"
        default:
            return "unknown"
    }
}

func listJobs(addr string) ([]job, error) {
    res, _ := httpGet("http://" + addr + "/api/v1/jobs")
    jobs := []job{}
    err := json.Unmarshal([]byte(res), &jobs)
    return jobs, err
}

func parseLocationHost(loc string) (string) {
    components := strings.Split(loc, ".")
    if len(components) == 1 {
        return components[0]
    }
    return components[len(components) - 2]
}

func resolveMoverAgent(endpoint, ns, loc string) (string, error) {
    scList, _ := services(endpoint, ns, "mover-agent")
    for _, svc := range(scList) {
        if parseLocationHost(loc) == parseLocationHost(svc.Tags.Loc) {
            return svc.Addr, nil
        }
    }
    return "", errors.New("No mover agent service found for " + loc)
}

func resolveService(endpoint, ns, svc, host, vol string) (service, error) {
    var loc string
    var scType string

    if svc + host + vol == "" {
        log.Fatalln("Please provide either 'svc', or 'host' and 'vol'")
    }
    for _, t := range([]string{"meta2", "rawx"}) {
        scList, err := services(endpoint, ns, t)
        if err != nil {
            log.Fatal(err)
        }
        for _, sc := range(scList) {
            if(svc != "" && sc.Addr == svc) {
                loc = sc.Tags.Loc
                scType = t
                break
            } else if(vol != "" && host != "" && vol == sc.Tags.Vol) {
                hostInLocation := host
                if strings.Index(sc.Tags.Loc, ".") > -1 {
                    hostInLocation += "."
                }
                if strings.Index(sc.Tags.Loc, hostInLocation) > -1 {
                    loc = host
                    scType = t
                    svc = sc.Addr
                    break
                }
            }
        }
        if scType != "" {
            break
        }
    }

    if loc == "" && svc != "" {
        log.Fatalf("Could not find service %s", svc)
    }
    if loc == "" && host != "" {
        log.Fatalf("Could not find service on host %s with volume %s", host, vol)
    }

    return service{Addr: svc, Location: loc, Type: scType, Volume: vol}, nil
}

func services(endpoint, ns, scType string) (serviceInfo, error){
    resp, err := httpGet("http://" + endpoint + "/v3.0/" + ns + "/conscience/list?type=" + scType)
    if err != nil {
        log.Fatal("Error in getting services from conscience: ", err)
        return nil, err
    }

    res := serviceInfo{}



    err = json.Unmarshal([]byte(resp), &res)
    if err != nil {
        log.Fatal("Error in unmarshalling services from conscience", err)
        return nil, err
    }

    return res, nil
}

func proxyAddr(basePath string, ns string) (string, error) {
	conf, err := readConf(path.Join(basePath, ns), "=")
	if err != nil {
		return "", err
	}
	addr := conf["proxy"]
	if len(addr) != 0 {
		return addr, nil
	}
	return "", errors.New("no proxy address found for namespace " + ns)
}

func readConf(path string, separator string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if pos := strings.Index(line, separator); pos > 0 {
			if key := strings.TrimSpace(line[:pos]); len(key) > 0 {
				value := ""
				if len(line) > pos {
					value = strings.TrimSpace(line[pos+1:])
				}
				config[key] = value
			}
		}
	}
	return config, nil
}
