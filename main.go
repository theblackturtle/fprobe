package main

import (
    "bufio"
    "crypto/sha1"
    "crypto/tls"
    "flag"
    "fmt"
    "net"
    "os"
    "regexp"
    "sort"
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
    client          *fasthttp.Client
    similarDetector *Similar
    timeout         time.Duration
    urlRegex        = regexp.MustCompile(`^(http|ws)s?://`)

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

func init() {
    client = &fasthttp.Client{
        NoDefaultUserAgentHeader: true,
        Dial: func(addr string) (net.Conn, error) {
            return fasthttp.DialDualStackTimeout(addr, 30*time.Second)
        },
        TLSConfig: &tls.Config{
            InsecureSkipVerify: true,
            Renegotiation:      tls.RenegotiateOnceAsClient, // For "local error: tls: no renegotiation"
        },
        // This also limits the maximum header size.
        ReadBufferSize:      28 * 1024,
        WriteBufferSize:     28 * 1024,
        MaxIdleConnDuration: time.Second,
    }
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

    // Get an idea from httprobe written by @tomnomnom
    var preferHTTPS bool
    flag.BoolVar(&preferHTTPS, "prefer-https", false, "oOnly try plain HTTP if HTTPS fails")

    var detectSimilarSites bool
    flag.BoolVar(&detectSimilarSites, "detect-similar", false, "Detect similar sites (careful when using this, this just using headers and cookies to generation hash)")

    var verbose bool
    flag.BoolVar(&verbose, "v", false, "Turn on verbose")

    var debug bool
    flag.BoolVar(&debug, "d", false, "Turn on debug")

    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "AUTHOR: @thebl4ckturtle - github.com/theblackturtle\n\nUsage of fprobe:\n")
        flag.PrintDefaults()
    }
    flag.Parse()

    timeout = time.Duration(to) * time.Second
    if detectSimilarSites {
        similarDetector = NewSimilar()
    }

    var wg sync.WaitGroup
    httpPool, _ := ants.NewPoolWithFunc(concurrency/2, func(i interface{}) {
        defer wg.Done()
        u := i.(string)
        urlWithScheme := "http://" + u
        success, v, err := isWorking(urlWithScheme, verbose)
        if success {
            if !verbose {
                fmt.Println(urlWithScheme)
            } else {
                if vj, err := jsoniter.MarshalToString(v); err == nil {
                    fmt.Println(vj)
                }
            }
        } else {
            if debug {
                fmt.Fprintf(os.Stderr, "[DEBUG] %s: %s\n", urlWithScheme, err)
            }
        }
    }, ants.WithPreAlloc(true))
    defer httpPool.Release()

    httpsPool, _ := ants.NewPoolWithFunc(concurrency/2, func(i interface{}) {
        defer wg.Done()
        u := i.(string)
        urlWithScheme := "https://" + u
        success, v, err := isWorking(urlWithScheme, verbose)
        if success {
            if !verbose {
                fmt.Println(urlWithScheme)
            } else {
                if vj, err := jsoniter.MarshalToString(v); err == nil {
                    fmt.Println(vj)
                }
            }
            if preferHTTPS {
                return
            }
        } else {
            if debug {
                fmt.Fprintf(os.Stderr, "[DEBUG] %s: %s\n", urlWithScheme, err)
            }
        }
        wg.Add(1)
        httpPool.Invoke(u)
    }, ants.WithPreAlloc(true))
    defer httpsPool.Release()

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
                wg.Add(1)
                _ = httpsPool.Invoke(ip)
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
                    wg.Add(1)
                    _ = httpsPool.Invoke(fmt.Sprintf("%s:%s", d, port))
                }
            }
            continue
        }

        if urlRegex.MatchString(line) {
            wg.Add(1)
            if strings.HasPrefix(line, "http://") {
                _ = httpPool.Invoke(strings.TrimPrefix(line, "http://"))
            } else {
                _ = httpsPool.Invoke(strings.TrimPrefix(line, "https://"))
            }
            continue
        }

        if !skipDefault {
            wg.Add(1)
            _ = httpsPool.Invoke(line)
        }

        for _, p := range probes {
            switch p {
            case "medium":
                for _, port := range portMedium {
                    wg.Add(1)
                    _ = httpsPool.Invoke(fmt.Sprintf("%s:%s", line, port))
                }
            case "large":
                for _, port := range portLarge {
                    wg.Add(1)
                    _ = httpsPool.Invoke(fmt.Sprintf("%s:%s", line, port))
                }
            case "xlarge":
                for _, port := range portXlarge {
                    wg.Add(1)
                    _ = httpsPool.Invoke(fmt.Sprintf("%s:%s", line, port))
                }
            default:
                pair := strings.SplitN(p, ":", 2)
                if len(pair) != 2 {
                    continue
                }
                wg.Add(1)
                if pair[0] == "http" {
                    _ = httpPool.Invoke(fmt.Sprintf("%s:%s", line, pair[1]))
                } else {
                    _ = httpsPool.Invoke(fmt.Sprintf("%s:%s", line, pair[1]))
                }
            }
        }
    }
    wg.Wait()
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

    err := client.DoTimeout(req, resp, timeout)
    if err != nil {
        return false, v, err
    }

    if similarDetector != nil {
        var headers []string
        resp.Header.VisitAll(func(key, _ []byte) {
            headers = append(headers, string(key))
        })
        sort.Strings(headers)

        var cookies []string
        resp.Header.VisitAllCookie(func(key, _ []byte) {
            cookies = append(cookies, string(key))
        })
        sort.Strings(cookies)
        hash := getHash(headers, cookies)
        // Return if this site's hash exists
        if !similarDetector.Add(hash) {
            return false, v, fmt.Errorf("similar another site")
        }
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

func getHash(headers, cookies []string) string {
    headerHash := strings.Join(headers, ",")
    cookieHash := strings.Join(cookies, ",")
    hash := fmt.Sprintf("%s,%s", headerHash, cookieHash)
    checksum := sha1.Sum([]byte(hash))
    return fmt.Sprintf("%x", checksum)
}
