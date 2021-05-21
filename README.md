# rao

Use @projectdiscovery [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) library to analyze http response file.

## Install
```
go get -u github.com/guervild/rao
```

## Usage

rao takes a file on stdin :
```
cat output.txt | rao -format <meg or curl>
```

The following format are supported:
- meg
- curl

## Format

### meg

[meg](https://github.com/tomnomnom/meg) output file can be used in input:
```
$ meg / https://github.com
$ cat out/github.com/56a9763339b64846c64d3cefdbd2ca40af0b9f2e | rao -format meg
https://github.com/ - [GitHub Pages, Ruby on Rails]

$ meg / https://gitlab.com
$ cat out/gitlab.com/2f59290ae0746e17c2264eaf8e34a62d172be358 | rao -format meg
https://gitlab.com/ - [Cloudflare]
```

### curl

curl with `-i` argument that include the HTTP response headers in the output is supported:
```
$ curl -s -i -k https://github.com | rao -format curl
 - [Ruby on Rails, GitHub Pages]

$ curl -s -i -k https://gitlab.com | rao -format curl
https://about.gitlab.com/ - [Cloudflare]
```

Sometimes the url might not be parsed from the response, but that does not impact the technologie detection.