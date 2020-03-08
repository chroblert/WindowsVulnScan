```shell
https://portal.msrc.microsoft.com/en-us/security-guidance/summary
||
https://portal.msrc.microsoft.com/zh-cn/security-guidance/advisory/ADV200003
||
https://portal.msrc.microsoft.com/zh-cn/security-guidance
https://portal.msrc.microsoft.com/en-us/security-guidance
```

```shell
POST /api/security-guidance/en-us/excel HTTP/1.1
Host: portal.msrc.microsoft.com
Connection: keep-alive
Content-Length: 509
Accept: application/json, text/plain, */*
Origin: https://portal.msrc.microsoft.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.75 Safari/537.36
Sec-Fetch-Mode: cors
Content-Type: application/json;charset=UTF-8
Sec-Fetch-Site: same-origin
Referer: https://portal.msrc.microsoft.com/en-us/security-guidance
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Cookie: MC1=GUID=d1e9c6f2e4764aa783f58b0014b7467e&HASH=d1e9&LV=201907&V=4&LU=1563270444852; MUID=0A3D3E6E27B5643B396333F3265F65AE; _ga=GA1.2.154170918.1563782191; MSCC=1564045372; LPVID=MxZTI5ZmNmNWE2YTAxODk3; utag_main=v_id:016c45c9aee9001ffaf3da01fbc003073005906b00bd0$_sn:1$_ss:1$_st:1564540741163$ses_id:1564538941163%3Bexp-session$_pn:1%3Bexp-session; optimizelyEndUserId=oeu1564629457139r0.4801813184222494; _mkto_trk=id:157-GQE-382&token:_mch-microsoft.com-1571045391152-13213; ctm={'pgv':6091864590169892|'vst':5653176317984654|'vstr':1286623662625240|'intr':1572932287646|'v':1|'lvst':6023}; AMCV_EA76ADE95776D2EC7F000101%40AdobeOrg=-1303530583%7CMCMID%7C11959062351296364190628513498173831208%7CMCAAMLH-1577954294%7C11%7CMCAAMB-1577954294%7C6G1ynYcLPuiQxYZrsz_pkqfLG9yMXBpb2zX5dvJdYQJzPXImdj0y%7CMCOPTOUT-1577356694s%7CNONE%7CMCSYNCS%7C411-18116%7CMCAID%7CNONE%7CMCIDTS%7C18257%7CvVersion%7C3.3.0%7CMCCIDH%7C-1534585596; mbox=PC#c5fd7ba98b6943419eb6cca6579fa271.22_8#1640594296|session#9bc0c1bceb114eea868d5c4f87b8cc07#1577351354; _fbp=fb.1.1577349498943.232320114; WT_FPC=id=2d5a9d31c9d0cd03ba41563987773627:lv=1577616726091:ss=1577616309143; _gid=GA1.2.2036083996.1582798861; RT="dm=microsoft.com&si=fwl9vfjml0q&ss=1582858586808&sl=2&tt=3620&obo=0&sh=1582858620845%3D2%3A0%3A3620%2C1582858589749%3D1%3A0%3A2489&rl=1&ld=1582858620845&r=https%3A%2F%2Fwww.microsoft.com%2Fen-us%2Fdownload%2F&ul=1582858620924&hd=1582858621735"; MS-CV=MvNsv/mk9Ey5/rBT.14; RPSShare=1; __RequestVerificationToken=d3glxouJkrX-tQygqU0Yoiolc3tYsLQl43h2XYbV66nDQgzZi9xpgrc8fNWfENS3gora903MPgOpsp-gdjHluXxgy-FkMQ4tEHZY3AfvwY81; smcflighting=100; ak_bmsc=68B052226C0320439A3AFBD46248CF1517DBAC9C625200005ED4585E09AB617E~plmJ+jyxHbCT/IX1dY/xzNrRfMjimVvSewhpnqRiiOejAmsoze9Z/Jq42PVWsh//5SzDxzVilOmWdSiq/I9PKNUQsbcrrnj7zMIgNIThPkKoSjsTI7R9umyAk6GKjvsUPrrZijiPZz5D1tXumAO0PRBM6zSrbjLT/oj371K5PfxmI+tw5jCoNqbelrdpHePm8qWrikiulWFzJKfdI8Yql96AyHvzCr4D3touzIjgyCQNg=; RPSMaybe=1582880228; msdn=L=zh-cn; bm_sv=5F1123780DBEB9CEF596C915C0FC2975~boykHeh7uKDVG6U5NGpgVe/Uyszex/34oPUcA6oJp5bLKXv1Iccfbyr3INkoEZkQqBLZU9GPPi9irr/gDz9BuZLLHCLcm1C+vvdFma80CpijicQV+fHvf6deuNU3b5VYy/ADx1MhyfHOj0e+66i2O7hDhE1KZe1rM2kKO6YAFnM=; MS0=a6077d7f85ea4159b34707b0487132cc

{"familyIds":[100000000,100000001,100000002,100000003,100000004,100000005,100000006,100000007,100000008,100000009,100000010,100000011,100000012],"productIds":[],"severityIds":[],"impactIds":[],"pageNumber":1,"pageSize":100,"includeCveNumber":true,"includeSeverity":false,"includeImpact":false,"orderBy":"publishedDate","orderByMonthly":"releaseDate","isDescending":true,"isDescendingMonthly":true,"queryText":"","isSearch":false,"filterText":"","fromPublishedDate":"01/01/1998","toPublishedDate":"02/28/2020"}
```

```sqlite
select CVEName,name from CVEKB where (name like "Windows 10%") and (<待替换> not in (select KBName from CVEKB where name like "windows 10%"));
```

