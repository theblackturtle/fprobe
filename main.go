package main

import (
    "bufio"
    "crypto/tls"
    "flag"
    "fmt"
    "net"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"

    "github.com/3th1nk/cidr"
    "github.com/json-iterator/go"
    "github.com/panjf2000/ants/v2"
    "github.com/valyala/fasthttp"
)

const AUTHOR = "@thebl4ckturtle - github.com/theblackturtle"

var (
    client    *fasthttp.Client
    errorPool sync.Pool
    urlRegex  = regexp.MustCompile(`^(http|ws)s?://`)

    timeout    time.Duration
    portMedium = []string{"8000", "8080", "8443"}
    portLarge  = []string{"81", "591", "2082", "2087", "2095", "2096", "3000", "8000", "8001", "8008", "8080", "8083", "8443", "8834", "8888"}
    portXlarge = []string{"81", "300", "591", "593", "832", "981", "1010", "1311", "2082", "2087", "2095", "2096", "2480", "3000", "3128", "3333", "4243", "4567", "4711", "4712", "4993", "5000", "5104", "5108", "5800", "6543", "7000", "7396", "7474", "8000", "8001", "8008", "8014", "8042", "8069", "8080", "8081", "8088", "8090", "8091", "8118", "8123", "8172", "8222", "8243", "8280", "8281", "8333", "8443", "8500", "8834", "8880", "8888", "8983", "9000", "9043", "9060", "9080", "9090", "9091", "9200", "9443", "9800", "9981", "12443", "16080", "18091", "18092", "20720", "28017"}
)

type probeArgs []string

func (p *probeArgs) Set(val string) error {
    *p = append(*p, val)
    return nil
}

func (p probeArgs) String() string {
    return strings.Join(p, ",")
}

type verboseStruct struct {
    Site        string `json:"site"`
    StatusCode  int    `json:"status_code"`
    Server      string `json:"server"`
    ContentType string `json:"content_type"`
    Location    string `json:"location"`
}

func main() {
    // Threads
    var concurrency int
    flag.IntVar(&concurrency, "c", 50, "Concurrency")

    // probe flags, get from httprobe
    var probes probeArgs
    flag.Var(&probes, "p", "add additional probe (proto:port)")

    // skip default probes flag, get from httprobe
    var skipDefault bool
    flag.BoolVar(&skipDefault, "s", false, "skip the default probes (http:80 and https:443)")

    // Time out flag
    var to int
    flag.IntVar(&to, "t", 9, "Timeout (seconds)")

    // Input file flag
    var inputFile string
    flag.StringVar(&inputFile, "i", "-", "Input file (default is stdin)")

    var sameLinePorts bool
    flag.BoolVar(&sameLinePorts, "l", false, "Use ports in the same line (google.com,2087,2086)")

    var cidrInput bool
    flag.BoolVar(&cidrInput, "cidr", false, "Generate IP addresses from CIDR")

    var verbose bool
    flag.BoolVar(&verbose, "v", false, "Turn on verbose")
    flag.Parse()

    timeout = time.Duration(to) * time.Second
    initClient()

    var wg sync.WaitGroup
    pool, _ := ants.NewPoolWithFunc(concurrency, func(i interface{}) {
        defer wg.Done()
        u := i.(string)
        if success, v, _ := isWorking(u, verbose); success {
            if !verbose {
                fmt.Println(u)
            } else {
                if vj, err := jsoniter.MarshalToString(v); err == nil {
                    fmt.Println(vj)
                }
            }
        }
    }, ants.WithPreAlloc(true))
    defer pool.Release()

    var sc *bufio.Scanner
    if inputFile == "" {
        fmt.Fprintln(os.Stderr, "Please check your input again")
        os.Exit(1)
    }
    if inputFile == "-" {
        sc = bufio.NewScanner(os.Stdin)
    } else {
        f, err := os.Open(inputFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error when open input file: %s\n", err)
            os.Exit(1)
        }
        defer f.Close()
        sc = bufio.NewScanner(f)
    }

    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if err := sc.Err(); err != nil {
            fmt.Fprintf(os.Stderr, "Error reading input file: %s\n", err)
            break
        }
        if line == "" {
            continue
        }

        if cidrInput {
            c, err := cidr.ParseCIDR(line)
            if err != nil {
                fmt.Fprintf(os.Stderr, "Failed to parse input as CIDR: %s\n", err)
                continue
            }
            if err := c.ForEachIP(func(ip string) error {
                wg.Add(2)
                _ = pool.Invoke("http://" + ip)
                _ = pool.Invoke("https://" + ip)
                return nil
            }); err != nil {
                fmt.Fprintf(os.Stderr, "Failed to parse input as CIDR: %s\n", err)
            }
            continue
        }

        if sameLinePorts {
            lineArgs := strings.Split(line, ",")
            if len(lineArgs) < 2 {
                continue
            }
            d, ports := lineArgs[0], lineArgs[1:]
            for _, port := range ports {
                if port := strings.TrimSpace(port); port != "" {
                    wg.Add(2)
                    _ = pool.Invoke(fmt.Sprintf("http://%s:%s", d, port))
                    _ = pool.Invoke(fmt.Sprintf("https://%s:%s", d, port))
                }
            }
            continue
        }

        if urlRegex.MatchString(line) {
            wg.Add(1)
            _ = pool.Invoke(line)
            continue
        }

        if !skipDefault {
            wg.Add(2)
            _ = pool.Invoke("http://" + line)
            _ = pool.Invoke("https://" + line)
        }

        for _, p := range probes {
            switch p {
            case "medium":
                for _, port := range portMedium {
                    wg.Add(2)
                    _ = pool.Invoke(fmt.Sprintf("http://%s:%s", line, port))
                    _ = pool.Invoke(fmt.Sprintf("https://%s:%s", line, port))
                }
            case "large":
                for _, port := range portLarge {
                    wg.Add(2)
                    _ = pool.Invoke(fmt.Sprintf("http://%s:%s", line, port))
                    _ = pool.Invoke(fmt.Sprintf("https://%s:%s", line, port))
                }
            case "xlarge":
                for _, port := range portXlarge {
                    wg.Add(2)
                    _ = pool.Invoke(fmt.Sprintf("http://%s:%s", line, port))
                    _ = pool.Invoke(fmt.Sprintf("https://%s:%s", line, port))
                }
            default:
                pair := strings.SplitN(p, ":", 2)
                if len(pair) != 2 {
                    continue
                }
                wg.Add(1)
                _ = pool.Invoke(fmt.Sprintf("%s://%s:%s", pair[0], line, pair[1]))
            }
        }
    }
    wg.Wait()
}

func initClient() {
    client = &fasthttp.Client{
        NoDefaultUserAgentHeader: true,
        Dial: func(addr string) (net.Conn, error) {
            return fasthttp.DialTimeout(addr, timeout)
        },
        TLSConfig: &tls.Config{
            InsecureSkipVerify: true,
            Renegotiation:      tls.RenegotiateOnceAsClient, // For "local error: tls: no renegotiation"
        },
        // This also limits the maximum header size.
        ReadBufferSize:  28 * 1024,
        WriteBufferSize: 28 * 1024,
    }
}

func isWorking(url string, verbose bool) (bool, *verboseStruct, error) {
    var v *verboseStruct
    req := fasthttp.AcquireRequest()
    defer fasthttp.ReleaseRequest(req)
    req.SetRequestURI(url)
    req.SetConnectionClose()

    resp := fasthttp.AcquireResponse()
    defer fasthttp.ReleaseResponse(resp)
    resp.SkipBody = true

    err := doRequestTimeout(req, resp)
    if err != nil {
        return false, v, err
    }
    if verbose {
        server := resp.Header.Peek(fasthttp.HeaderServer)
        contentType := resp.Header.Peek(fasthttp.HeaderContentType)
        location := resp.Header.Peek(fasthttp.HeaderLocation)
        v = &verboseStruct{
            Site:        url,
            StatusCode:  resp.StatusCode(),
            Server:      string(server),
            ContentType: string(contentType),
            Location:    string(location),
        }
    }
    return true, v, nil
}

func doRequestTimeout(req *fasthttp.Request, resp *fasthttp.Response) (err error) {
    var ch chan error
    chv := errorPool.Get()
    if chv == nil {
        chv = make(chan error, 1)
    }
    ch = chv.(chan error)

    go func() {
        err := client.Do(req, resp)
        ch <- err
    }()

    tc := fasthttp.AcquireTimer(timeout)
    select {
    case err = <-ch:
        errorPool.Put(chv)
    case <-tc.C:
        err = fasthttp.ErrTimeout
    }
    fasthttp.ReleaseTimer(tc)
    return
}
