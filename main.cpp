#include <iostream>
#include "lianjia_sha256.h"

using namespace std;


int main() {

    unsigned char outbuf[32];
    unsigned char data_buf[] = "accessKeyId=LdmD9deEB8Dtp0Nl&appinfo-s=HomeLink;9.45.0;9450100&channel-s=Android_360&device-id-s=fac40f0391168928;DuDFnB6WLldJWRdns1jsaeVArgfNah+wI9iVc1tIn+f8T+4MsuMZbE4rsC0WKJw0SWZaafIyqTYb9G3O86+nIeBg;rEN8z4WjvdRgoHOBuR8rq+oTlPuGISa8GAp4TKK7YHN6vVjD9GAf7ax2MuKohHMaUNplUDXSmly+NAoQ9O02WWJ4WpVJX2RMrAUEMVPmRiJJwL9/lcNdSUP2iMiXGiPS&hardware-s=xiaomi;MI 6X&host=usercenter.api.ke.com&method=POST&nonce=bxQz787wXvmdDnyzSfGF3QIgoqcpf81f&path=/sdk/v1/authentication/authenticate&signedHeaders=Device-id-s,User-Agent,AppInfo-s,Hardware-s,Channel-s,SystemInfo-s&systeminfo-s=android;9&timestamp=1638540225&user-agent=com.homelink.android/9.45.0/1.2.0 (Android 9;xiaomi MI+6X)";
    unsigned char md5_str[33];
    gen_salt(md5_str);

    gen_sign( data_buf,md5_str,outbuf);
    for (int i = 1; i <= sizeof(outbuf); ++i) {
        printf("%02X", outbuf[i - 1]);
    }
    printf("\n------加密结束---------\n");
    return 0;
}


