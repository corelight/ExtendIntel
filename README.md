# ExtendIntel
This package extends the Intel package to log more fields

Intel log
---------

Without this package, the standard intel.log would have content like the following:

    {
      "@path":"intel",
      "@sensor":"Lab-AP200",
      "@timestamp":"2023-01-06T05:13:38.841292Z",
      "ts":"2023-01-06T05:13:38.841292Z",
      "uid":"CNh51N3dSRfMZG1Pt4",
      "id.orig_h":"195.133.40.86",
      "id.orig_p":64910,
      "id.resp_h":"192.168.13.20",
      "id.resp_p":80,
      "seen.indicator":"77.247.181.165",
      "seen.indicator_type":"Intel::ADDR",
      "seen.where":"Conn::IN_ORIG",
      "matched": [
        "Intel::ADDR"
      ],
      "sources": [
        "blocklist_de",
        "cinsscore_ci_badguys",
        "blocklist_net_ua",
        "Mandiant",
        "dshield_block"
      ],
    }


If the ExtendIntel Zeek package is loaded, the intel.log will be enriched with additional content like the following:

    {
      "confidence": [99],
      "desc": [
        "Mandiant Threat Intellegence"
        ]
      "lastseen": [
        "2023-01-03T16:10:54Z"
        ],
      "firstseen": [
        "2021-03-20T10:10:01Z"
        ],
      "url": [
        "https://advantage.mandiant.com/"
        ],
      "reports": [
        "ID:23-00000242, Type:News Analysis"
      ],
      "campaigns": [],
      "associated": [
        "ID:threat-actor--b7e371c2-724e-5ffa-9e3c-9b1410513c27, Name:FIN13; ID:threat-actor--8211bc17-9216-5e83-b54d-d1b04add12f3, Name:APT28; ID:threat-actor--7a39953e-0dae-569a-9d49-d52a4a8865b1, Name:APT29; ID:threat-actor--2f0ab36a-02a6-59f7-ac23-bcd824cc7c8e, Name:FIN4"
      ],
      "category": [
        "exploit",
        "exploit/vuln-scanning, exploit"
      ],
    }
