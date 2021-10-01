/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <check.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <orcania.h>
#include <yder.h>
#include <ulfius.h>
#include <rhonabwy.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "user1"
#define USER_PASSWORD "password"
#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "oidc_ciba"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_JWT_TYPE_RSA "rsa"
#define PLUGIN_JWT_KEY_SIZE "256"
#define PLUGIN_CIBA_DEFAULT_EXPIRATION 600
#define PLUGIN_CIBA_MAXIMUM_EXPIRATION 1200
#define SCOPE_LIST "scope1 openid"
#define SCOPE_1 "scope1"
#define SCOPE_2 "openid"
#define CLIENT_ID_POLL "client_ciba_poll"
#define CLIENT_ID_PING "client_ciba_ping"
#define CLIENT_ID_PUSH "client_ciba_push"
#define CLIENT_SECRET "passwordciba"
#define CLIENT_NOTIFICATION_ENDPOINT_PING "https://localhost:2422/cb"
#define CLIENT_NOTIFICATION_ENDPOINT_PUSH "https://localhost:2423/cb"
#define CLIENT_REDIRECT "https://client.tld"
#define CLIENT_PUBKEY_PARAM "pubkey"
#define CIBA_CLIENT_NOTIFICATION_TOKEN "ZBMDEshXMWMv8KUbBSUnbRgEYpvM8LyA"
#define CIBA_BINDING_MESSAGE "CIBA message grut"
#define CB_KEY "cert/server.key"
#define CB_CRT "cert/server.crt"
#define CIBA_SMTP_PORT 2525
#define CIBA_SMTP_FROM "glewlwyd@example.com"
#define CIBA_SMTP_SUBJECT "CIBA message"
#define CIBA_SMTP_BODY_PATTERN "Connect "

const char pubkey_1_pem[] = "-----BEGIN PUBLIC KEY-----\n"\
                            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxaF1egmmQ+0/AAEcv/Jd\n"\
                            "TCBxi7A05VvDvRgaYzOEWqJF3qv3b6ifD4E4C9+cir6tIyCOJ2WXE4TV9fCWBQjI\n"\
                            "omacdQjdEwMAEWYYVEz4PPpWZDEeCKKgsz5DnLNyPznMiom82vDREvSqG+yxAEbk\n"\
                            "W1r+MtcFRd4YSZyJYDSVJ+t2VL7Nt/Gxao/MC8rJP/QHzSbWjwruSwW3JM+75wds\n"\
                            "JUbHhyIZ5lQ2u06d68ZA9Q4T60i+zE49yoLd8+PIjcrhM3kYIJkcTKyjWqZEV+we\n"\
                            "16eroS8PX/YN5tw4Od+fKb6I0XILhiyCqKlOg3FHdY8iAK75atI6TvX73ei+zSF3\n"\
                            "UyEFjDTcnhe6mPHL9REIVmb0+n70feP/SFQqaFRaamxBOkBPsVa9NP4zLJiRn71j\n"\
                            "ff7opHcT7zaR19cigQxsYmd+rZnhiH+UXel8P7kVTM7OCc7LRSJPG6xY4FtpWE2q\n"\
                            "abrGaUfBCMGtrH0GqjtbNCnBeBeCiijpN5XPqnGlSXpXrd3mjldlrFhiKVSlnvyp\n"\
                            "ekdAzA0WvpraBy351TzMsXphokchoynpdP04Pyv7DtI6SrU7sn5QZGoZtRVzNjOE\n"\
                            "CljVD4HZmc7Xw/kpCcb3sBtT9KOTlGd/ocn7D4Tw04jCCjmPOWhX/kKTrD4Mf+wv\n"\
                            "kUNxrz0Ea7PClAQf+HeZrjcCAwEAAQ==\n"\
                            "-----END PUBLIC KEY-----";
const char privkey_1_pem[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
                            "MIIJKwIBAAKCAgEAxaF1egmmQ+0/AAEcv/JdTCBxi7A05VvDvRgaYzOEWqJF3qv3\n"\
                            "b6ifD4E4C9+cir6tIyCOJ2WXE4TV9fCWBQjIomacdQjdEwMAEWYYVEz4PPpWZDEe\n"\
                            "CKKgsz5DnLNyPznMiom82vDREvSqG+yxAEbkW1r+MtcFRd4YSZyJYDSVJ+t2VL7N\n"\
                            "t/Gxao/MC8rJP/QHzSbWjwruSwW3JM+75wdsJUbHhyIZ5lQ2u06d68ZA9Q4T60i+\n"\
                            "zE49yoLd8+PIjcrhM3kYIJkcTKyjWqZEV+we16eroS8PX/YN5tw4Od+fKb6I0XIL\n"\
                            "hiyCqKlOg3FHdY8iAK75atI6TvX73ei+zSF3UyEFjDTcnhe6mPHL9REIVmb0+n70\n"\
                            "feP/SFQqaFRaamxBOkBPsVa9NP4zLJiRn71jff7opHcT7zaR19cigQxsYmd+rZnh\n"\
                            "iH+UXel8P7kVTM7OCc7LRSJPG6xY4FtpWE2qabrGaUfBCMGtrH0GqjtbNCnBeBeC\n"\
                            "iijpN5XPqnGlSXpXrd3mjldlrFhiKVSlnvypekdAzA0WvpraBy351TzMsXphokch\n"\
                            "oynpdP04Pyv7DtI6SrU7sn5QZGoZtRVzNjOECljVD4HZmc7Xw/kpCcb3sBtT9KOT\n"\
                            "lGd/ocn7D4Tw04jCCjmPOWhX/kKTrD4Mf+wvkUNxrz0Ea7PClAQf+HeZrjcCAwEA\n"\
                            "AQKCAgEAiK7oXuT5lxUoc0pRpfdry1DM9v2BN/fFYqye42kn6r88b4qj8RfAGqsW\n"\
                            "JjAbRmIlwJutdVXvrNI8YIJqX0T57kflgZQFwjZa/62KuhMZxKKmyVinGvXPCujP\n"\
                            "PjtlkpDZBB/K++l90Axi8jk7GaPuH7jJAkRwIyg9x/t5j44OcrOI/YeRI90HBVo6\n"\
                            "lxVDJvYRxzNLRVccA8sKJW1+2YPqqcVQDgfpvcEUsWroEb7mAhYgdKO1QfwDBGKK\n"\
                            "OzmY5WghZMYlh7YdOnJT8Ef6EIz/r8sJCstPaOD2MGqygGRG4koiuiiUC9IQ87FU\n"\
                            "2deowoehzrM1UUnghefesFVeUOUKbr3Gh7rv5fYzijwtel2fAW29qjdhgqoCq/WQ\n"\
                            "fQlkT2QnJjeh2Fdr5JFmm84KgTdikOvlROVGQRZkBNCOq0Y/skSr9FDC0PAzU2kA\n"\
                            "0iXhwUAlWFQlud2Mx4moFwDj40RXpsGNaR6fDXv0fpS5Y1c3NeSU+yC0ycX8/BwE\n"\
                            "Uq63CcWocATmDrD2IdDnIbv/abjMyh18GIaJLLdx1DZ/cwQdFGgGaqigQZT/pSuu\n"\
                            "fqLIAXGT+wg0SdP/sSbKCV79DA/k34FC4WkP81aiMaKtbA7CJZgEdEFc/S5vXts3\n"\
                            "HvDiCFroLEedfInQxkFrI4gyudAZ5YLujlr3fYsJNB96B0GHnGECggEBAPQQSKxv\n"\
                            "01Oky+jENQwxiZcpI4a5PzLPFFCgEqIjSRamCzrCQ07e97iqhU1b8IvRwxDtX358\n"\
                            "pFKAq7tmwpN2QQb1T9fqUwCpeQuMwRsZwoaM7ZcTSj2FZ/2djN1ixQfzqQ21VxkM\n"\
                            "RbrdyExqCSJXnHMcLeiFmu81dVopV2iwDbUQv4jZe/ktPUTH4HKle48Y0v9pu22l\n"\
                            "D5cknAQGB1gUNfyJ0PbUxZMITrZDz4khhYgxqvJ7GluYRNv2tezV+bb5leXbSLDr\n"\
                            "RgTKqcl5ZjkgLm9FRNGZZAmlsCHEeB3nvCs2ePQYDuLgEkNtuu39kpLFJO6j70bj\n"\
                            "nvpaIAcDVpPmEE8CggEBAM9L09Grg2uSrNUGfj9pfpsMn0k5kqV0n3WjX9z5ZLkw\n"\
                            "LNNrs0SJjb93haO2MPNlyYhctCpPKnfHJKZWaLhFDV6xr+ubf7c3DbBJjPhlV8dU\n"\
                            "kgmHfIqWDPl6pzN0xC61zC4IE15LgW/JEMpq53fRWnIHdufs+105QO8YOo0CVYKY\n"\
                            "jqut4hVbYRBSTaeVLb1vj/yhaL0qV7orQoTrpr6Bg20nftBBa+8Md/B5l0QyiSfv\n"\
                            "OjKnXsjULQdQGbtypQZvu2jUasnUVUQHBgeF5W5WFj8qCGGnmehqY6QissipLoRM\n"\
                            "cGPaV/gJKisgcorF7sSU/QzcBUmPk377LkzZXGNUYZkCggEBALL4hfI9BmCdxhFo\n"\
                            "X+YTJWw9dJnEmf1uMN12pHNVILGFDVMHRUg+5LT8BkhWFSzSoxJ0nsQoLm95f3Uq\n"\
                            "w6BS5RhvJx+T603e+K5phumSmD0GduuD77rxavJlZ/ioBwfvu5Yb1kS95RxEqi6u\n"\
                            "ywft6wHWNiv+XUDwmJ+HFVvlTgfqwileIjT04argT0yC4PpsH73AEPs0QRx6chXZ\n"\
                            "PeVu3K/Vd/Co0kEhpGavjy5l8H+QvGSXtRpZrJUIcxu7RSTSHQOzK7jgrjWxT5Q4\n"\
                            "e6eEW8ioqPByZRNV9rSsV9DGMAwYI9YLFk90NLBRdPQ0MBmEi7KbcEkxfVDkafv6\n"\
                            "jLBj0q0CggEBAJldyYY7dczVxMcKucbinwfJq+N6E/QTt5JKYDdV0F5utQtqiEQx\n"\
                            "3MyGejooJkk9yn/3zlfrIElj7cqe7XU/qWeg4L3Y2wHLWnZNxF1WZT4VZMJmGg9S\n"\
                            "eqDtTNz2C9tfJ4P695FxHX99681GkKAGJPtuaFuo6kQLgu4iJ9eBnZA0nIGJ8VXJ\n"\
                            "uKNhsRBGf4PDEW1gYeRqemNDdEBxNHmHypusd9dOP7OpruccnnyXQwBnrtAhIjBF\n"\
                            "QldBvPgBFvUPH0GsvqE6VicxZxWTy635RRZQW8kcPfNFGxkpjsqE2OSKxTArL6BT\n"\
                            "733e0L+5NzD75cho1ASblA2DerriqcbXfCkCggEBAILHVNisODhO4GC8P709DqGd\n"\
                            "VdufLZf2Bl7AwjWyYTkpEzEfQCHHUnmOoTCn+OEvnn9lWiaCaTijtlUmos0fCfvS\n"\
                            "QLk9elciIOmlRk8G1EtnnzYQsTmerLoMJBgQ02hhip8GK47Y7mbZIjaPB625Dv8F\n"\
                            "4RHd9ZiTzXTGcNc6bldWlNNbbqw9DWS1DORPhdQEPU424qcYvHq/eklFCujWukO8\n"\
                            "ul3FEZYnTcth2ODSFMb0a0SCuDGkGI8BDI+/4n6+4wIlAXtc8Vt9Ko8WxJjCK/v2\n"\
                            "Ae9x05eknWZj0JxuyoAjPtJApp0pt25omJwZr/lY5i8T0cL6dDF5nZcA9hN//eo=\n"\
                            "-----END RSA PRIVATE KEY-----\n";
const char pubkey_2_pem[] = "-----BEGIN PUBLIC KEY-----\n"\
                            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAosjEKF8XSrvPPGuQYUz9\n"\
                            "C7wLHvoJ3UAR3vpHFdJa+Z/N9STXYVh67UtCnM7RW+mbO7BuFFmT1WB2jnLnWzaT\n"\
                            "zeG3hC/A44imv2uU1mtOIgt5iFiF5N+XZs9opsM9jWsUW2J8uFPK1ohdnXxWkFAf\n"\
                            "7fTJx2fJbO7fgxjM5GIq7s1f7vbPaAaNTH8h4hnGRKuWg+n15FKjYmGUDD5SQj5d\n"\
                            "yMrbZx/8DbGm0XX//rQvLf3eXP2r3HFFTbWn9HcimZF6csqhmh4g4Rt5Ou2JcZlr\n"\
                            "krbSo8gyONelZ+kvKKJwAZG0+6Pu4+MgSHdwGe1B2jUmeQ1EAelsIWvLArCH4c/t\n"\
                            "3JYFdDe9fMfUcof6C3aseMaa8HW1WHhaH8erSnP5klF0NGhhRWB1lYSCWQ/hT9yg\n"\
                            "vlTJQ8v/2ocFbsZUi8lQ6bL9Lc4piHyMOeK/2ozm13wk9OHGfLxKYEtzs5V6oevg\n"\
                            "D7daJ0rtS/h21iLguqKt5rwe7Rzy3boMxVlNGFux0RSP5rzjoGQ/vkuuSiWgyygm\n"\
                            "TIheeOV/wCds6IDR7s2zrgBxQvsUK1isp5YipHVo4AOuPxNcxGnxLkt0DA7AOYCw\n"\
                            "h2jngVWmjKgzSYG0EHiiLUrXyMFp4xhyTBLSQpWZn65o8jwABqzWtodMirsZsawI\n"\
                            "GihzXtw00vRRJDnVpE7EQUUCAwEAAQ==\n"\
                            "-----END PUBLIC KEY-----\n";
const char privkey_2_pem[] = "-----BEGIN RSA PRIVATE KEY-----\n"\
                            "MIIJJwIBAAKCAgEAosjEKF8XSrvPPGuQYUz9C7wLHvoJ3UAR3vpHFdJa+Z/N9STX\n"\
                            "YVh67UtCnM7RW+mbO7BuFFmT1WB2jnLnWzaTzeG3hC/A44imv2uU1mtOIgt5iFiF\n"\
                            "5N+XZs9opsM9jWsUW2J8uFPK1ohdnXxWkFAf7fTJx2fJbO7fgxjM5GIq7s1f7vbP\n"\
                            "aAaNTH8h4hnGRKuWg+n15FKjYmGUDD5SQj5dyMrbZx/8DbGm0XX//rQvLf3eXP2r\n"\
                            "3HFFTbWn9HcimZF6csqhmh4g4Rt5Ou2JcZlrkrbSo8gyONelZ+kvKKJwAZG0+6Pu\n"\
                            "4+MgSHdwGe1B2jUmeQ1EAelsIWvLArCH4c/t3JYFdDe9fMfUcof6C3aseMaa8HW1\n"\
                            "WHhaH8erSnP5klF0NGhhRWB1lYSCWQ/hT9ygvlTJQ8v/2ocFbsZUi8lQ6bL9Lc4p\n"\
                            "iHyMOeK/2ozm13wk9OHGfLxKYEtzs5V6oevgD7daJ0rtS/h21iLguqKt5rwe7Rzy\n"\
                            "3boMxVlNGFux0RSP5rzjoGQ/vkuuSiWgyygmTIheeOV/wCds6IDR7s2zrgBxQvsU\n"\
                            "K1isp5YipHVo4AOuPxNcxGnxLkt0DA7AOYCwh2jngVWmjKgzSYG0EHiiLUrXyMFp\n"\
                            "4xhyTBLSQpWZn65o8jwABqzWtodMirsZsawIGihzXtw00vRRJDnVpE7EQUUCAwEA\n"\
                            "AQKCAgAgeAsoQk9TCML9OjdCMSkH/in5s8Xj67Ok1ib3o02iHM3n58FOGWfrjOds\n"\
                            "f5Qi0SW1ciuCw5tJJESBhUnAV9KDblI8e4nt2IPqCntViXG8OK21FHMgg7ifOR+W\n"\
                            "o7rTSlh1Id/epFgBEpIZp4NcpZ64x+q3a2wx3jOW4ot7wljt6OkJsRENnsDwUStg\n"\
                            "/eMeL1uGVFRHhnQwW2Y8SvH9ZJMwScYZe7e6w4SSowa8txPyCIEh6zcscStxpJor\n"\
                            "mNe96daSrvgs1XWZcPFtX5PapM9gJDc/k97wl5LWdxyA7mWI6pc+2iP8MIFv8uLZ\n"\
                            "SQmpjJBv9MVr3DNFN0r27l8sG11GIPMEg9Y01uEK4PZ5oASRNJbdddTOY9KWsYL4\n"\
                            "IxRV6ZU5ZGe0+EQWBeJnPfr4cyJd59fWC1hA8FUBAjWc8NimmMAaPu76xW+1Cqwo\n"\
                            "HgBDNzhQur+20eImvD9MZsVJDRAI8nYe+cVN4FaLEogK9iJFcyjv+R1QEofv8/+N\n"\
                            "qiibNZtff2mF9Y5YLrZQ3b0eNAzcY3VuQyN2iWsqjmXy4F1AP8ZUAyp2S6d3onDx\n"\
                            "+m4ua6EUB462gxUCxbYh34IbL+OyLX1xuBEetUd7j++7fK+8K5Dkw/RGd2K+D0m8\n"\
                            "sz4uPzcmxtZ9QbZQSE/JyBM8VzC5Mqy1NyJdBJcsosV62tywwQKCAQEAz/mQXsGj\n"\
                            "ErtO+6zr+x7YTF9PeUrATsTNtMDASGlbUIGLXcCwr5sE1lcT7zfMXS6xnP0NQnkF\n"\
                            "HIfgsBPEwMKSnRXNrS127TTvvxU6CzzDO5K1u7q6hzUvuDhj0iZjCSotBC4Dgg39\n"\
                            "G1J3N5YY4D+2jtS4yWsdIdCuUB/Sel6/1x6jfmkFSgLSxUATycX06/b+WSAFGS40\n"\
                            "Z5B+n8gfKF2OvuvdTi1uNr8T4EQXMZRQG8hgn7WRcrHuKmanI/jsWs5SiOPArKf7\n"\
                            "E+m7glguu9D5dqID5KI7kCUGGf+IhcRvcWoF2dZDTFKiyzfWNidVWj7ua5H+wGbl\n"\
                            "SYDQ+1UO2sFxKwKCAQEAyF/CL5HFZbUmA/igc8FN46vD1OQWlVqFEXk8B5kgK6hX\n"\
                            "EiA9lRo0/UeG6/o61vgjtI1F1CKjHPqNUaiCmTXVBXqWWxXiyRqcCBGpZPx2zup0\n"\
                            "CxcCGQUKYPqYBqoazipUtRIasyr8qGoFwJ23am+HLfK4hCa/+JZIn5cmWxdtZbwN\n"\
                            "I1raal596coHl23fnMpmnnHOf9RVSgLgcrtzZlou+zQq5QTymBoB0AWiCTt6aBB9\n"\
                            "dcr1M89F32O6WU9lPHdRDXTiZKFfofP+9+5NSKk8EV5/NKbc4q1czl6OQNB1iaij\n"\
                            "GdW1HbRK6OMn/QPSPrq/4b0vx1378dw1SCynnsp/TwKCAQAjzJCWTvyUD9vzpHtm\n"\
                            "WZPf6ZQTi9N4e5XxJDC1BjWqsPHdbHq9b5CwmIKc7dzmuU/ndwOeSpifpZ/+jxiS\n"\
                            "GawFECi8Q5QyFqeiG7RHFOmCSqmvq9/JwFT7f/FmzibEABeJnaYK7/9+gX51+gdE\n"\
                            "KpNxGJrKSP7VwEcREbk4STD6hZKdAtTfPYcsXvBJDiMvru9vRfy6reJlZVD2jgsW\n"\
                            "9qvIn28TsuxCzjdMpkvbw+zaK26+bxGfTZNyhwMERSfiJZu9Zn7W+X9VmSkmsakx\n"\
                            "uTIHwrGq3GYmVMktFnhYlkycmCRzr9cbvym4k17zKWgexbBiodnZIp0bPuo6KRUK\n"\
                            "gLvLAoIBAGrV29S/NW/AQU+2vd5aP+xXRef54SyrAe5KJL6sX2HHtP0eIZehTIWL\n"\
                            "IJ4rYjoCPg9jj8rG2Q93a+gRH+kOsdDlBsv0BGJThMQsnpQQpEw457yN/PlYHauN\n"\
                            "kYdkJTyth1KwH3pOPj6RoRWNQiFG692M3+LeQlcJ0hj9X18MQ7ENrjeelnxGe34u\n"\
                            "0RNlaufPZx2t8ntnvD3lAMVLuwDkrs4Th5dqpuqAW10N09J2WxKnUC2BFHIWXtv3\n"\
                            "8YDy+zhdKeMx4g/jlvjj/ps0/RHz4eok51Asc/OMmcIS2mgmfbTzLFt2/cWjvpkj\n"\
                            "nMujwPLfYbW7yIDVVKMlVWdxH8Jjl7MCggEAbNq+mJjepyGY5mXTlzAcBFY5HqlD\n"\
                            "x+Ssapo1waswzRhnXKB15zqU+LQfotBBp7pKxWCytwgOmV2toZf/R0Sqinohh52D\n"\
                            "0mCvTYldTB5tUpKpnhEGZuOZ24BTtrqNAw2X5NRKTflttiVJgfrMCSDIR8NNX4aw\n"\
                            "GB8iUNZLyn4e5Zjfa7cLCwn7ngINpU1TaCY9gbHSsYcVcpX7ro6Vr93ox6cRtapB\n"\
                            "WElzAPXDF0YKMiKzA4fTqVtbamVHz64k7xgWVwdWXDbdqOWOtI0weeeHMy2Y9Ktz\n"\
                            "7eXh0rK0fG1c35qJ+V61oXdyfapmI7uGH2R5J+Q2LDJw/3AMGb6oCsPfdQ==\n"\
                            "-----END RSA PRIVATE KEY-----\n";

struct _u_request admin_req;
struct _u_request user_req;
int counter = 0;

void add_client_ciba(const char * client_id,
                     const char * backchannel_token_delivery_mode,
                     const char * backchannel_client_notification_endpoint,
                     const char * backchannel_authentication_request_signing_alg,
                     const char * backchannel_authentication_request_enc_alg) {
  json_t * j_parameters = json_pack("{sssos[s]sos[ssss]sssss[sss]ssss*ss*ss*}",
                                    "client_id", client_id,
                                    "enabled", json_true(),
                                    "redirect_uri",
                                      CLIENT_REDIRECT,
                                    "confidential", json_true(),
                                    "token_endpoint_auth_method",
                                      "client_secret_post",
                                      "client_secret_basic",
                                      "client_secret_jwt",
                                      "private_key_jwt",
                                    "client_secret", CLIENT_SECRET,
                                    CLIENT_PUBKEY_PARAM, pubkey_1_pem,
                                    "authorization_type",
                                      "urn:openid:params:grant-type:ciba",
                                      "token",
                                      "id_token",
                                    "backchannel_token_delivery_mode", backchannel_token_delivery_mode,
                                    "backchannel_client_notification_endpoint", backchannel_client_notification_endpoint,
                                    "backchannel_authentication_request_signing_alg", backchannel_authentication_request_signing_alg,
                                    "backchannel_authentication_request_enc_alg", backchannel_authentication_request_enc_alg);
  ck_assert_ptr_ne(NULL, j_parameters);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}

void client_grant_scopes(const char * scopes) {
  json_t * j_grant = json_pack("{ss}", "scope", scopes);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID_POLL, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID_PING, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID_PUSH, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_grant);
}

char * get_id_token(const char * client_id) {
  struct _u_request req;
  struct _u_response resp;
  char * id_token = NULL;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth?response_type=token%20id_token&g_continue&client_id=",
                                                       U_OPT_HTTP_URL_APPEND, client_id,
                                                       U_OPT_HTTP_URL_APPEND, "&redirect_uri=" CLIENT_REDIRECT "&nonce=nonce1234&scope=openid",
                                                       U_OPT_HTTP_VERB, "GET",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token="));
  ck_assert_ptr_ne(NULL, id_token);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  return id_token;
}

static int callback_client_notification_endpoint_ping(const struct _u_request * request, struct _u_response * response, void * user_data) {
  counter++;
  json_t * j_body = ulfius_get_json_body_request(request, NULL);
  ck_assert_str_eq("Bearer " CIBA_CLIENT_NOTIFICATION_TOKEN, u_map_get(request->map_header, "Authorization"));
  ck_assert_str_eq(user_data, json_string_value(json_object_get(j_body, "auth_req_id")));
  json_decref(j_body);
  return U_CALLBACK_CONTINUE;
}

static int callback_client_notification_endpoint_push(const struct _u_request * request, struct _u_response * response, void * user_data) {
  jwt_t * jwt;
  counter++;
  json_t * j_body = ulfius_get_json_body_request(request, NULL);
  ck_assert_str_eq("Bearer " CIBA_CLIENT_NOTIFICATION_TOKEN, u_map_get(request->map_header, "Authorization"));
  ck_assert_str_eq(user_data, json_string_value(json_object_get(j_body, "auth_req_id")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "access_token")));
  ck_assert_str_eq("bearer", json_string_value(json_object_get(j_body, "token_type")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "refresh_token")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "id_token")));
  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(json_string_value(json_object_get(j_body, "access_token")), R_PARSE_NONE, 0));
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "scope"));
  r_jwt_free(jwt);
  json_decref(j_body);
  return U_CALLBACK_CONTINUE;
}

static int callback_client_notification_endpoint_push_reduced_scope(const struct _u_request * request, struct _u_response * response, void * user_data) {
  jwt_t * jwt;
  counter++;
  json_t * j_body = ulfius_get_json_body_request(request, NULL);
  ck_assert_str_eq("Bearer " CIBA_CLIENT_NOTIFICATION_TOKEN, u_map_get(request->map_header, "Authorization"));
  ck_assert_str_eq(user_data, json_string_value(json_object_get(j_body, "auth_req_id")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "access_token")));
  ck_assert_str_eq("bearer", json_string_value(json_object_get(j_body, "token_type")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "refresh_token")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "id_token")));
  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(json_string_value(json_object_get(j_body, "access_token")), R_PARSE_NONE, 0));
  ck_assert_str_eq(SCOPE_2, r_jwt_get_claim_str_value(jwt, "scope"));
  r_jwt_free(jwt);
  json_decref(j_body);
  return U_CALLBACK_CONTINUE;
}

START_TEST(test_oidc_ciba_add_plugin_user_code_no_email_no)
{
  json_t * j_param = json_pack("{sssssss{sssssssssssisisisososososososososossso sosisisosososososo}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", PLUGIN_JWT_TYPE_RSA,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", privkey_2_pem,
                                  "cert", pubkey_2_pem,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "allow-non-oidc", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-id-token-enabled", json_true(),
                                  "auth-type-device-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "request-parameter-allow", json_true(),
                                  "client-pubkey-parameter", CLIENT_PUBKEY_PARAM,
                                  "request-parameter-allow-encrypted", json_true(),
                                  
                                  "oauth-ciba-allowed", json_true(),
                                  "oauth-ciba-default-expiry", PLUGIN_CIBA_DEFAULT_EXPIRATION,
                                  "oauth-ciba-maximum-expiry", PLUGIN_CIBA_MAXIMUM_EXPIRATION,
                                  "oauth-ciba-mode-poll-allowed", json_true(),
                                  "oauth-ciba-mode-ping-allowed", json_true(),
                                  "oauth-ciba-mode-push-allowed", json_true(),
                                  "oauth-ciba-allow-https-non-secure", json_true(),
                                  "oauth-ciba-user-code-allowed", json_false(),
                                  "oauth-ciba-email-allowed", json_false());
  ck_assert_ptr_ne(NULL, j_param);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_ciba_add_plugin_user_code_email_no)
{
  json_t * j_param = json_pack("{sssssss{sssssssssssisisisososososososososossso sosisisososososossso}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", PLUGIN_JWT_TYPE_RSA,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", privkey_2_pem,
                                  "cert", pubkey_2_pem,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "allow-non-oidc", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-id-token-enabled", json_true(),
                                  "auth-type-device-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "request-parameter-allow", json_true(),
                                  "client-pubkey-parameter", CLIENT_PUBKEY_PARAM,
                                  "request-parameter-allow-encrypted", json_true(),
                                  
                                  "oauth-ciba-allowed", json_true(),
                                  "oauth-ciba-default-expiry", PLUGIN_CIBA_DEFAULT_EXPIRATION,
                                  "oauth-ciba-maximum-expiry", PLUGIN_CIBA_MAXIMUM_EXPIRATION,
                                  "oauth-ciba-mode-poll-allowed", json_true(),
                                  "oauth-ciba-mode-ping-allowed", json_true(),
                                  "oauth-ciba-mode-push-allowed", json_true(),
                                  "oauth-ciba-allow-https-non-secure", json_true(),
                                  "oauth-ciba-user-code-allowed", json_true(),
                                  "oauth-ciba-user-code-property", "username",
                                  "oauth-ciba-email-allowed", json_false());
  ck_assert_ptr_ne(NULL, j_param);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_ciba_add_plugin_user_code_no_email)
{
  json_t * j_param = json_pack("{sssssss{sssssssssssisisisososososososososossso sosisisososososo sosssisosssss{s{sossss}}}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", PLUGIN_JWT_TYPE_RSA,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", privkey_2_pem,
                                  "cert", pubkey_2_pem,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "allow-non-oidc", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-id-token-enabled", json_true(),
                                  "auth-type-device-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "request-parameter-allow", json_true(),
                                  "client-pubkey-parameter", CLIENT_PUBKEY_PARAM,
                                  "request-parameter-allow-encrypted", json_true(),
                                  
                                  "oauth-ciba-allowed", json_true(),
                                  "oauth-ciba-default-expiry", PLUGIN_CIBA_DEFAULT_EXPIRATION,
                                  "oauth-ciba-maximum-expiry", PLUGIN_CIBA_MAXIMUM_EXPIRATION,
                                  "oauth-ciba-mode-poll-allowed", json_true(),
                                  "oauth-ciba-mode-ping-allowed", json_true(),
                                  "oauth-ciba-mode-push-allowed", json_true(),
                                  "oauth-ciba-allow-https-non-secure", json_true(),
                                  "oauth-ciba-user-code-allowed", json_false(),
                                  
                                  "oauth-ciba-email-allowed", json_true(),
                                  "oauth-ciba-email-host", "localhost",
                                  "oauth-ciba-email-port", CIBA_SMTP_PORT,
                                  "oauth-ciba-email-use-tls", json_false(),
                                  "oauth-ciba-email-from", CIBA_SMTP_FROM,
                                  "oauth-ciba-email-user-lang-property", "lang",
                                  "oauth-ciba-email-templates",
                                    "en",
                                      "oauth-ciba-email-defaultLang", json_true(),
                                      "oauth-ciba-email-subject", CIBA_SMTP_SUBJECT,
                                      "oauth-ciba-email-body-pattern", CIBA_SMTP_BODY_PATTERN "{CONNECT_URL}");
  ck_assert_ptr_ne(NULL, j_param);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_ciba_add_plugin_expires_soon)
{
  json_t * j_param = json_pack("{sssssss{sssssssssssisisisososososososososossso sosisisosososososo}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", PLUGIN_JWT_TYPE_RSA,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", privkey_2_pem,
                                  "cert", pubkey_2_pem,
                                  "access-token-duration", 3600,
                                  "refresh-token-duration", 1209600,
                                  "code-duration", 600,
                                  "refresh-token-rolling", json_true(),
                                  "allow-non-oidc", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-id-token-enabled", json_true(),
                                  "auth-type-device-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "request-parameter-allow", json_true(),
                                  "client-pubkey-parameter", CLIENT_PUBKEY_PARAM,
                                  "request-parameter-allow-encrypted", json_true(),
                                  
                                  "oauth-ciba-allowed", json_true(),
                                  "oauth-ciba-default-expiry", 1,
                                  "oauth-ciba-maximum-expiry", PLUGIN_CIBA_MAXIMUM_EXPIRATION,
                                  "oauth-ciba-mode-poll-allowed", json_true(),
                                  "oauth-ciba-mode-ping-allowed", json_true(),
                                  "oauth-ciba-mode-push-allowed", json_true(),
                                  "oauth-ciba-allow-https-non-secure", json_true(),
                                  "oauth-ciba-user-code-allowed", json_false(),
                                  "oauth-ciba-email-allowed", json_false());
  ck_assert_ptr_ne(NULL, j_param);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_ciba_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_ciba_add_client_poll)
{
  add_client_ciba(CLIENT_ID_POLL, "poll", NULL, NULL, NULL);
}
END_TEST

START_TEST(test_oidc_ciba_add_client_ping)
{
  add_client_ciba(CLIENT_ID_PING, "ping", CLIENT_NOTIFICATION_ENDPOINT_PING, NULL, NULL);
}
END_TEST

START_TEST(test_oidc_ciba_add_client_push)
{
  add_client_ciba(CLIENT_ID_PUSH, "push", CLIENT_NOTIFICATION_ENDPOINT_PUSH, NULL, NULL);
}
END_TEST

START_TEST(test_oidc_ciba_delete_client_poll)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID_POLL, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_ciba_delete_client_ping)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID_PING, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_ciba_delete_client_push)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID_PUSH, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_ciba_client_grant_scopes)
{
  client_grant_scopes(SCOPE_LIST);
}
END_TEST

START_TEST(test_oidc_ciba_client_grant_none)
{
  client_grant_scopes("");
}
END_TEST

START_TEST(test_oidc_ciba_request_client_notification_token_missing)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_client_notification_token_invalid_chars)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN"~;",
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_client_notification_token_invalid_small_length)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", "small" ,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_client_notification_token_invalid_large_length)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN CIBA_CLIENT_NOTIFICATION_TOKEN "0", // Last char "0" so length is 1025
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_login_hint_missing)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_login_hint_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\"error\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_login_hint_error_key)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"error\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_login_hint_error_format)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "error",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_login_hint_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, json_object_get(j_body, "auth_req_id"));
  ck_assert_int_eq(PLUGIN_CIBA_DEFAULT_EXPIRATION, json_integer_value(json_object_get(j_body, "expires_in")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_id_token_hint_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * id_token = get_id_token(CLIENT_ID_PING);
  id_token[o_strlen(id_token) - 4] = '\0';

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "id_token_hint", id_token,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  o_free(id_token);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_id_token_hint_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * id_token = get_id_token(CLIENT_ID_PING);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "id_token_hint", id_token,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, json_object_get(j_body, "auth_req_id"));
  ck_assert_int_eq(PLUGIN_CIBA_DEFAULT_EXPIRATION, json_integer_value(json_object_get(j_body, "expires_in")));
  
  o_free(id_token);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_login_hint_token_invalid_signature)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  jwt_t * jwt;
  jwk_t * jwk;
  char * token;
  
  ck_assert_int_eq(RHN_OK, r_jwt_init(&jwt));
  ck_assert_int_eq(RHN_OK, r_jwt_set_full_claims_json_str(jwt, "{\"username\":\""USER_USERNAME"\"}"));
  ck_assert_int_eq(RHN_OK, r_jwt_set_sign_alg(jwt, R_JWA_ALG_HS256));
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, "error"));
  ck_assert_ptr_ne(NULL, token = r_jwt_serialize_signed(jwt, jwk, 0));
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint_token", token,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_login_hint_token_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  jwt_t * jwt;
  jwk_t * jwk;
  char * token;
  
  ck_assert_int_eq(RHN_OK, r_jwt_init(&jwt));
  ck_assert_int_eq(RHN_OK, r_jwt_set_full_claims_json_str(jwt, "{\"username\":\""USER_USERNAME"\"}"));
  ck_assert_int_eq(RHN_OK, r_jwt_set_sign_alg(jwt, R_JWA_ALG_HS256));
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, CLIENT_SECRET));
  ck_assert_ptr_ne(NULL, token = r_jwt_serialize_signed(jwt, jwk, 0));
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint_token", token,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, json_object_get(j_body, "auth_req_id"));
  ck_assert_int_eq(PLUGIN_CIBA_DEFAULT_EXPIRATION, json_integer_value(json_object_get(j_body, "expires_in")));
  
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_login_hint_too_much)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  jwt_t * jwt;
  jwk_t * jwk;
  char * token;
  
  ck_assert_int_eq(RHN_OK, r_jwt_init(&jwt));
  ck_assert_int_eq(RHN_OK, r_jwt_set_full_claims_json_str(jwt, "{\"username\":\""USER_USERNAME"\"}"));
  ck_assert_int_eq(RHN_OK, r_jwt_set_sign_alg(jwt, R_JWA_ALG_HS256));
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, "error"));
  ck_assert_ptr_ne(NULL, token = r_jwt_serialize_signed(jwt, jwk, 0));
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint_token", token,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_signed_request_login_hint_invalid_signature)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  jwt_t * jwt;
  jwk_t * jwk;
  char * token;
  time_t now;
  int rnd;
  char jti[12] = {0};
  
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  snprintf(jti, 11, "jti_%06d", rnd);
  time(&now);
  ck_assert_int_eq(RHN_OK, r_jwt_init(&jwt));
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, "error"));
  ck_assert_int_eq(RHN_OK, r_jwt_set_properties(jwt, RHN_OPT_CLAIM_STR_VALUE, "aud", PLUGIN_ISS,
                                                     RHN_OPT_CLAIM_STR_VALUE, "iss", CLIENT_ID_PING,
                                                     RHN_OPT_CLAIM_INT_VALUE, "exp", now+60,
                                                     RHN_OPT_CLAIM_INT_VALUE, "iat", now,
                                                     RHN_OPT_CLAIM_INT_VALUE, "nbf", now,
                                                     RHN_OPT_CLAIM_STR_VALUE, "jti", jti,
                                                     RHN_OPT_CLAIM_STR_VALUE, "scope", SCOPE_LIST,
                                                     RHN_OPT_CLAIM_STR_VALUE, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                     RHN_OPT_CLAIM_STR_VALUE, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                     RHN_OPT_SIG_ALG, R_JWA_ALG_HS256,
                                                     RHN_OPT_SIGN_KEY_JWK, jwk,
                                                     RHN_OPT_NONE));
  ck_assert_ptr_ne(NULL, token = r_jwt_serialize_signed(jwt, jwk, 0));

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_POST_BODY_PARAMETER, "request", token,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(401, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_client", json_string_value(json_object_get(j_body, "error")));
  
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_signed_request_login_hint_replay_jti)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  jwt_t * jwt;
  jwk_t * jwk;
  char * token;
  time_t now;
  int rnd;
  char jti[12] = {0};
  
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  snprintf(jti, 11, "jti_%06d", rnd);
  time(&now);
  ck_assert_int_eq(RHN_OK, r_jwt_init(&jwt));
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, CLIENT_SECRET));
  ck_assert_int_eq(RHN_OK, r_jwt_set_properties(jwt, RHN_OPT_CLAIM_STR_VALUE, "aud", PLUGIN_ISS,
                                                     RHN_OPT_CLAIM_STR_VALUE, "iss", CLIENT_ID_PING,
                                                     RHN_OPT_CLAIM_INT_VALUE, "exp", now+60,
                                                     RHN_OPT_CLAIM_INT_VALUE, "iat", now,
                                                     RHN_OPT_CLAIM_INT_VALUE, "nbf", now,
                                                     RHN_OPT_CLAIM_STR_VALUE, "jti", jti,
                                                     RHN_OPT_CLAIM_STR_VALUE, "scope", SCOPE_LIST,
                                                     RHN_OPT_CLAIM_STR_VALUE, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                     RHN_OPT_CLAIM_STR_VALUE, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                     RHN_OPT_SIG_ALG, R_JWA_ALG_HS256,
                                                     RHN_OPT_SIGN_KEY_JWK, jwk,
                                                     RHN_OPT_NONE));
  ck_assert_ptr_ne(NULL, token = r_jwt_serialize_signed(jwt, jwk, 0));

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_POST_BODY_PARAMETER, "request", token,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(401, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_client", json_string_value(json_object_get(j_body, "error")));
  
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_signed_request_login_hint_invalid_aud)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  jwt_t * jwt;
  jwk_t * jwk;
  char * token;
  time_t now;
  int rnd;
  char jti[12] = {0};
  
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  snprintf(jti, 11, "jti_%06d", rnd);
  time(&now);
  ck_assert_int_eq(RHN_OK, r_jwt_init(&jwt));
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, CLIENT_SECRET));
  ck_assert_int_eq(RHN_OK, r_jwt_set_properties(jwt, RHN_OPT_CLAIM_STR_VALUE, "aud", "error",
                                                     RHN_OPT_CLAIM_STR_VALUE, "iss", CLIENT_ID_PING,
                                                     RHN_OPT_CLAIM_INT_VALUE, "exp", now+60,
                                                     RHN_OPT_CLAIM_INT_VALUE, "iat", now,
                                                     RHN_OPT_CLAIM_INT_VALUE, "nbf", now,
                                                     RHN_OPT_CLAIM_STR_VALUE, "jti", jti,
                                                     RHN_OPT_CLAIM_STR_VALUE, "scope", SCOPE_LIST,
                                                     RHN_OPT_CLAIM_STR_VALUE, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                     RHN_OPT_CLAIM_STR_VALUE, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                     RHN_OPT_SIG_ALG, R_JWA_ALG_HS256,
                                                     RHN_OPT_SIGN_KEY_JWK, jwk,
                                                     RHN_OPT_NONE));
  ck_assert_ptr_ne(NULL, token = r_jwt_serialize_signed(jwt, jwk, 0));

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_POST_BODY_PARAMETER, "request", token,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(401, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_request", json_string_value(json_object_get(j_body, "error")));
  
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_signed_request_login_hint_invalid_iss)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  jwt_t * jwt;
  jwk_t * jwk;
  char * token;
  time_t now;
  int rnd;
  char jti[12] = {0};
  
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  snprintf(jti, 11, "jti_%06d", rnd);
  time(&now);
  ck_assert_int_eq(RHN_OK, r_jwt_init(&jwt));
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, CLIENT_SECRET));
  ck_assert_int_eq(RHN_OK, r_jwt_set_properties(jwt, RHN_OPT_CLAIM_STR_VALUE, "aud", PLUGIN_ISS,
                                                     RHN_OPT_CLAIM_STR_VALUE, "iss", "error",
                                                     RHN_OPT_CLAIM_INT_VALUE, "exp", now+60,
                                                     RHN_OPT_CLAIM_INT_VALUE, "iat", now,
                                                     RHN_OPT_CLAIM_INT_VALUE, "nbf", now,
                                                     RHN_OPT_CLAIM_STR_VALUE, "jti", jti,
                                                     RHN_OPT_CLAIM_STR_VALUE, "scope", SCOPE_LIST,
                                                     RHN_OPT_CLAIM_STR_VALUE, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                     RHN_OPT_CLAIM_STR_VALUE, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                     RHN_OPT_SIG_ALG, R_JWA_ALG_HS256,
                                                     RHN_OPT_SIGN_KEY_JWK, jwk,
                                                     RHN_OPT_NONE));
  ck_assert_ptr_ne(NULL, token = r_jwt_serialize_signed(jwt, jwk, 0));

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_POST_BODY_PARAMETER, "request", token,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(401, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_client", json_string_value(json_object_get(j_body, "error")));
  
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_signed_request_login_hint_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  jwt_t * jwt;
  jwk_t * jwk;
  char * token;
  time_t now;
  int rnd;
  char jti[12] = {0};
  
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  snprintf(jti, 11, "jti_%06d", rnd);
  time(&now);
  ck_assert_int_eq(RHN_OK, r_jwt_init(&jwt));
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, CLIENT_SECRET));
  ck_assert_int_eq(RHN_OK, r_jwt_set_properties(jwt, RHN_OPT_CLAIM_STR_VALUE, "aud", PLUGIN_ISS,
                                                     RHN_OPT_CLAIM_STR_VALUE, "iss", CLIENT_ID_PING,
                                                     RHN_OPT_CLAIM_INT_VALUE, "exp", now+60,
                                                     RHN_OPT_CLAIM_INT_VALUE, "iat", now,
                                                     RHN_OPT_CLAIM_INT_VALUE, "nbf", now,
                                                     RHN_OPT_CLAIM_STR_VALUE, "jti", jti,
                                                     RHN_OPT_CLAIM_STR_VALUE, "scope", SCOPE_LIST,
                                                     RHN_OPT_CLAIM_STR_VALUE, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                     RHN_OPT_CLAIM_STR_VALUE, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                     RHN_OPT_SIG_ALG, R_JWA_ALG_HS256,
                                                     RHN_OPT_SIGN_KEY_JWK, jwk,
                                                     RHN_OPT_NONE));
  ck_assert_ptr_ne(NULL, token = r_jwt_serialize_signed(jwt, jwk, 0));

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_POST_BODY_PARAMETER, "request", token,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, json_object_get(j_body, "auth_req_id"));
  ck_assert_int_eq(PLUGIN_CIBA_DEFAULT_EXPIRATION, json_integer_value(json_object_get(j_body, "expires_in")));
  
  o_free(token);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_client_assertion_request_login_hint_invalid_signature)
{
  struct _u_request req;
  struct _u_response resp;
  jwt_t * jwt_request = NULL;
  jwk_t * jwk;
  char * request;
  int rnd;
  char jti[12] = {0};
  
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  snprintf(jti, 11, "jti_%06d", rnd);
  ck_assert_int_eq(r_jwt_init(&jwt_request), RHN_OK);
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, "error"));
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_HS256), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt_request, jwk, NULL), RHN_OK);
  r_jwt_set_claim_str_value(jwt_request, "iss", CLIENT_ID_PING);
  r_jwt_set_claim_str_value(jwt_request, "sub", CLIENT_ID_PING);
  r_jwt_set_claim_str_value(jwt_request, "aud", SERVER_URI "/" PLUGIN_NAME "/ciba");
  r_jwt_set_claim_str_value(jwt_request, "jti", jti);
  r_jwt_set_claim_int_value(jwt_request, "exp", time(NULL)+60);
  r_jwt_set_claim_int_value(jwt_request, "iat", time(NULL));
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_POST_BODY_PARAMETER, "client_assertion", request,
                                                       U_OPT_POST_BODY_PARAMETER, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(401, resp.status);
  
  r_jwk_free(jwk);
  o_free(request);
  r_jwt_free(jwt_request);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_client_assertion_request_login_hint_invalid_aud)
{
  struct _u_request req;
  struct _u_response resp;
  jwt_t * jwt_request = NULL;
  jwk_t * jwk;
  char * request;
  int rnd;
  char jti[12] = {0};
  
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  snprintf(jti, 11, "jti_%06d", rnd);
  ck_assert_int_eq(r_jwt_init(&jwt_request), RHN_OK);
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, CLIENT_SECRET));
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_HS256), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt_request, jwk, NULL), RHN_OK);
  r_jwt_set_claim_str_value(jwt_request, "iss", CLIENT_ID_PING);
  r_jwt_set_claim_str_value(jwt_request, "sub", CLIENT_ID_PING);
  r_jwt_set_claim_str_value(jwt_request, "aud", SERVER_URI "/" PLUGIN_NAME "/error");
  r_jwt_set_claim_str_value(jwt_request, "jti", jti);
  r_jwt_set_claim_int_value(jwt_request, "exp", time(NULL)+60);
  r_jwt_set_claim_int_value(jwt_request, "iat", time(NULL));
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_POST_BODY_PARAMETER, "client_assertion", request,
                                                       U_OPT_POST_BODY_PARAMETER, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(401, resp.status);
  
  r_jwk_free(jwk);
  o_free(request);
  r_jwt_free(jwt_request);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_client_assertion_request_login_hint_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  jwt_t * jwt_request = NULL;
  jwk_t * jwk;
  char * request;
  int rnd;
  char jti[12] = {0};
  
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  snprintf(jti, 11, "jti_%06d", rnd);
  ck_assert_int_eq(r_jwt_init(&jwt_request), RHN_OK);
  ck_assert_ptr_ne(NULL, jwk = r_jwk_quick_import(R_IMPORT_PASSWORD, CLIENT_SECRET));
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_HS256), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt_request, jwk, NULL), RHN_OK);
  r_jwt_set_claim_str_value(jwt_request, "iss", CLIENT_ID_PING);
  r_jwt_set_claim_str_value(jwt_request, "sub", CLIENT_ID_PING);
  r_jwt_set_claim_str_value(jwt_request, "aud", SERVER_URI "/" PLUGIN_NAME "/ciba");
  r_jwt_set_claim_str_value(jwt_request, "jti", jti);
  r_jwt_set_claim_int_value(jwt_request, "exp", time(NULL)+60);
  r_jwt_set_claim_int_value(jwt_request, "iat", time(NULL));
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_POST_BODY_PARAMETER, "client_assertion", request,
                                                       U_OPT_POST_BODY_PARAMETER, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, json_object_get(j_body, "auth_req_id"));
  ck_assert_int_eq(PLUGIN_CIBA_DEFAULT_EXPIRATION, json_integer_value(json_object_get(j_body, "expires_in")));
  
  r_jwk_free(jwk);
  o_free(request);
  r_jwt_free(jwt_request);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_user_list)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "binding_message", CIBA_BINDING_MESSAGE,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_ge(json_array_size(j_body), 1);
  ck_assert_str_eq(CLIENT_ID_PING, json_string_value(json_object_get(json_array_get(j_body, 0), "client_id")));
  ck_assert_str_eq(CIBA_BINDING_MESSAGE, json_string_value(json_object_get(json_array_get(j_body, 0), "binding_message")));
  ck_assert_int_gt(json_string_length(json_object_get(json_array_get(j_body, 0), "user_req_id")), 0);
  ck_assert_int_eq(json_array_size(json_object_get(json_array_get(j_body, 0), "scopes")), 2);
  ck_assert_int_gt(json_string_length(json_object_get(json_array_get(j_body, 0), "connect_uri")), 0);
  ck_assert_int_gt(json_string_length(json_object_get(json_array_get(j_body, 0), "cancel_uri")), 0);
  json_decref(j_body);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_user_check)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  size_t nb_ciba;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_ge(nb_ciba = json_array_size(j_body), 1);
  ulfius_clean_response(&resp);
  ck_assert_int_eq(run_simple_test(NULL, "GET", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")), NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html"), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")), NULL, NULL, NULL, NULL, 302, NULL, NULL, "login.html"), 1);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", json_string_value(json_object_get(json_array_get(j_body, 0), "cancel_uri")), NULL, NULL, NULL, NULL, 302, NULL, NULL, "ciba_message=cancelled"), 1);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(nb_ciba-1,  json_array_size(j_body));
  ulfius_clean_response(&resp);
  json_decref(j_body);
}
END_TEST

START_TEST(test_oidc_ciba_user_check_accept)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  size_t nb_ciba;
  char * url;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_POLL,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_ge(nb_ciba = json_array_size(j_body), 1);
  ulfius_clean_response(&resp);
  url = msprintf("%s&g_continue", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")));
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "ciba_message=complete"), 1);
  o_free(url);
  
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_int_eq(nb_ciba-1,  json_array_size(j_body));
  ulfius_clean_response(&resp);
  json_decref(j_body);
}
END_TEST

START_TEST(test_oidc_ciba_poll_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * url, * auth_req_id;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_POLL,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, auth_req_id = o_strdup(json_string_value(json_object_get(j_body, "auth_req_id"))));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_POLL,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", "error",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_grant", json_string_value(json_object_get(j_body, "error")));
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_POLL,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", auth_req_id,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("authorization_pending", json_string_value(json_object_get(j_body, "error")));
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  url = msprintf("%s&g_continue", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")));
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "ciba_message=complete"), 1);
  o_free(url);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_POLL,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", auth_req_id,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(auth_req_id, json_string_value(json_object_get(j_body, "auth_req_id")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "access_token")));
  ck_assert_str_eq("bearer", json_string_value(json_object_get(j_body, "token_type")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "refresh_token")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "id_token")));
  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(json_string_value(json_object_get(j_body, "access_token")), R_PARSE_NONE, 0));
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "scope"));
  r_jwt_free(jwt);

  o_free(auth_req_id);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_ping_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * url, * auth_req_id, * key_pem, * cert_pem;
  struct _u_instance instance;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, auth_req_id = o_strdup(json_string_value(json_object_get(j_body, "auth_req_id"))));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_instance(&instance, 2422, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "cb", 0, &callback_client_notification_endpoint_ping, auth_req_id), U_OK);
  counter = 0;
  
  key_pem = read_file(CB_KEY);
  cert_pem = read_file(CB_CRT);
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, key_pem, cert_pem), U_OK);
  o_free(key_pem);
  o_free(cert_pem);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", "error",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_grant", json_string_value(json_object_get(j_body, "error")));
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", auth_req_id,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("authorization_pending", json_string_value(json_object_get(j_body, "error")));
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  url = msprintf("%s&g_continue", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")));
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "ciba_message=complete"), 1);
  o_free(url);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", auth_req_id,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(auth_req_id, json_string_value(json_object_get(j_body, "auth_req_id")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "access_token")));
  ck_assert_str_eq("bearer", json_string_value(json_object_get(j_body, "token_type")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "refresh_token")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "id_token")));
  ck_assert_int_eq(1, counter);
  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(json_string_value(json_object_get(j_body, "access_token")), R_PARSE_NONE, 0));
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "scope"));
  r_jwt_free(jwt);

  o_free(auth_req_id);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_oidc_ciba_push_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * url, * auth_req_id, * key_pem, * cert_pem;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PUSH,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, auth_req_id = o_strdup(json_string_value(json_object_get(j_body, "auth_req_id"))));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_instance(&instance, 2423, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "cb", 0, &callback_client_notification_endpoint_push, auth_req_id), U_OK);
  counter = 0;
  
  key_pem = read_file(CB_KEY);
  cert_pem = read_file(CB_CRT);
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, key_pem, cert_pem), U_OK);
  o_free(key_pem);
  o_free(cert_pem);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  url = msprintf("%s&g_continue", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")));
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "ciba_message=complete"), 1);
  o_free(url);
  json_decref(j_body);

  ck_assert_int_eq(1, counter);

  o_free(auth_req_id);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_oidc_ciba_poll_reduced_scope_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * url, * auth_req_id;
  jwt_t * jwt;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_POLL,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, auth_req_id = o_strdup(json_string_value(json_object_get(j_body, "auth_req_id"))));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  client_grant_scopes(SCOPE_2);
  
  url = msprintf("%s&g_continue", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")));
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "ciba_message=complete"), 1);
  o_free(url);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_POLL,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", auth_req_id,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq(auth_req_id, json_string_value(json_object_get(j_body, "auth_req_id")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "access_token")));
  ck_assert_str_eq("bearer", json_string_value(json_object_get(j_body, "token_type")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "refresh_token")));
  ck_assert_ptr_ne(NULL, json_string_value(json_object_get(j_body, "id_token")));
  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(json_string_value(json_object_get(j_body, "access_token")), R_PARSE_NONE, 0));
  ck_assert_str_eq(SCOPE_2, r_jwt_get_claim_str_value(jwt, "scope"));

  client_grant_scopes(SCOPE_LIST);
  
  r_jwt_free(jwt);
  o_free(auth_req_id);
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_push_reduced_scope_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * url, * auth_req_id, * key_pem, * cert_pem;
  struct _u_instance instance;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PUSH,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, auth_req_id = o_strdup(json_string_value(json_object_get(j_body, "auth_req_id"))));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_instance(&instance, 2423, NULL, NULL), U_OK);
  ck_assert_int_eq(ulfius_add_endpoint_by_val(&instance, "POST", NULL, "cb", 0, &callback_client_notification_endpoint_push_reduced_scope, auth_req_id), U_OK);
  counter = 0;
  
  key_pem = read_file(CB_KEY);
  cert_pem = read_file(CB_CRT);
  ck_assert_int_eq(ulfius_start_secure_framework(&instance, key_pem, cert_pem), U_OK);
  o_free(key_pem);
  o_free(cert_pem);
  
  client_grant_scopes(SCOPE_2);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&user_req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba_user_list", U_OPT_HTTP_VERB, "GET", U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&user_req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  url = msprintf("%s&g_continue", json_string_value(json_object_get(json_array_get(j_body, 0), "connect_uri")));
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "ciba_message=complete"), 1);
  o_free(url);
  json_decref(j_body);

  ck_assert_int_eq(1, counter);

  client_grant_scopes(SCOPE_LIST);
  
  o_free(auth_req_id);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_oidc_ciba_request_user_code_invalid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_POST_BODY_PARAMETER, "user_code", "error",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_user_code", json_string_value(json_object_get(j_body, "error")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_ciba_request_user_code_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_POST_BODY_PARAMETER, "user_code", USER_USERNAME,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, json_object_get(j_body, "auth_req_id"));
  ck_assert_int_eq(PLUGIN_CIBA_DEFAULT_EXPIRATION, json_integer_value(json_object_get(j_body, "expires_in")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

#define BACKLOG_MAX  (10)
#define BUF_SIZE  4096
#define STREQU(a,b)  (strcmp(a, b) == 0)

struct smtp_manager {
  char * mail_data;
  unsigned int port;
  int sockfd;
  const char * body_pattern;
};

/**
 * 
 * Function that emulates a very simple SMTP server
 * Taken from Kenneth Finnegan's ccsmtp program
 * https://gist.github.com/PhirePhly/2914635
 * This function is under the GPL2 license
 * 
 */
static void handle_smtp (struct smtp_manager * manager) {
  int rc, i;
  char buffer[BUF_SIZE], bufferout[BUF_SIZE];
  int buffer_offset = 0;
  buffer[BUF_SIZE-1] = '\0';

  // Flag for being inside of DATA verb
  int inmessage = 0;

  sprintf(bufferout, "220 ulfius.tld SMTP CCSMTP\r\n");
  send(manager->sockfd, bufferout, strlen(bufferout), 0);

  while (1) {
    fd_set sockset;
    struct timeval tv;

    FD_ZERO(&sockset);
    FD_SET(manager->sockfd, &sockset);
    tv.tv_sec = 120; // Some SMTP servers pause for ~15s per message
    tv.tv_usec = 0;

    // Wait tv timeout for the server to send anything.
    select(manager->sockfd+1, &sockset, NULL, NULL, &tv);

    if (!FD_ISSET(manager->sockfd, &sockset)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Socket timed out", manager->sockfd);
      break;
    }

    int buffer_left = BUF_SIZE - buffer_offset - 1;
    if (buffer_left == 0) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Command line too long", manager->sockfd);
      sprintf(bufferout, "500 Too long\r\n");
      send(manager->sockfd, bufferout, strlen(bufferout), 0);
      buffer_offset = 0;
      continue;
    }

    rc = recv(manager->sockfd, buffer + buffer_offset, buffer_left, 0);
    if (rc == 0) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Remote host closed socket", manager->sockfd);
      break;
    }
    if (rc == -1) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Error on socket", manager->sockfd);
      break;
    }

    buffer_offset += rc;

    char *eol;

    // Only process one line of the received buffer at a time
    // If multiple lines were received in a single recv(), goto
    // back to here for each line
    //
processline:
    eol = strstr(buffer, "\r\n");
    if (eol == NULL) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Haven't found EOL yet", manager->sockfd);
      continue;
    }

    // Null terminate each line to be processed individually
    eol[0] = '\0';

    if (!inmessage) { // Handle system verbs
      // Replace all lower case letters so verbs are all caps
      for (i=0; i<4; i++) {
        if (islower(buffer[i])) {
          buffer[i] += 'A' - 'a';
        }
      }
      // Null-terminate the verb for strcmp
      buffer[4] = '\0';

      // Respond to each verb accordingly.
      // You should replace these with more meaningful
      // actions than simply printing everything.
      //
      if (STREQU(buffer, "HELO")) { // Initial greeting
        sprintf(bufferout, "250 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "MAIL")) { // New mail from...
        sprintf(bufferout, "250 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "RCPT")) { // Mail addressed to...
        sprintf(bufferout, "250 Ok recipient\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "DATA")) { // Message contents...
        sprintf(bufferout, "354 Continue\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
        inmessage = 1;
      } else if (STREQU(buffer, "RSET")) { // Reset the connection
        sprintf(bufferout, "250 Ok reset\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "NOOP")) { // Do nothing.
        sprintf(bufferout, "250 Ok noop\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "QUIT")) { // Close the connection
        sprintf(bufferout, "221 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
        break;
      } else { // The verb used hasn't been implemented.
        sprintf(bufferout, "502 Command Not Implemented\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      }
    } else { // We are inside the message after a DATA verb.
      if (0 == o_strncmp(manager->body_pattern, buffer, o_strlen(manager->body_pattern))) {
        manager->mail_data = o_strdup(buffer+o_strlen(manager->body_pattern));
      }
      if (STREQU(buffer, ".")) { // A single "." signifies the end
        sprintf(bufferout, "250 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
        inmessage = 0;
      }
    }

    // Shift the rest of the buffer to the front
    memmove(buffer, eol+2, BUF_SIZE - (eol + 2 - buffer));
    buffer_offset -= (eol - buffer) + 2;

    // Do we already have additional lines to process? If so,
    // commit a horrid sin and goto the line processing section again.
    if (strstr(buffer, "\r\n")) 
      goto processline;
  }

  // All done. Clean up everything and exit.
  shutdown(manager->sockfd, SHUT_WR);
  close(manager->sockfd);
}

static void * simple_smtp(void * args) {
  struct smtp_manager * manager = (struct smtp_manager *)args;
  int server_fd; 
  struct sockaddr_in address; 
  int opt = 1; 
  int addrlen = sizeof(address); 
  
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) != 0) {
    if (!setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = INADDR_ANY;
      address.sin_port = htons( manager->port );
         
      if (!bind(server_fd, (struct sockaddr *)&address, sizeof(address))) {
        if (listen(server_fd, 3) >= 0) {
          if ((manager->sockfd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
            handle_smtp(manager);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error accept");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error listen");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error bind");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error setsockopt");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error socket");
  }
  
  shutdown(server_fd, SHUT_RDWR);
  close(server_fd);

  pthread_exit(NULL);
}

START_TEST(test_oidc_ciba_request_email_ok)
{
  struct smtp_manager manager;
  pthread_t thread;

  manager.mail_data = NULL;
  manager.port = CIBA_SMTP_PORT;
  manager.sockfd = 0;
  manager.body_pattern = CIBA_SMTP_BODY_PATTERN;
  pthread_create(&thread, NULL, simple_smtp, &manager);
  
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_PING,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, json_object_get(j_body, "auth_req_id"));
  ck_assert_int_eq(PLUGIN_CIBA_DEFAULT_EXPIRATION, json_integer_value(json_object_get(j_body, "expires_in")));
  pthread_join(thread, NULL);
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  o_free(manager.mail_data);
}
END_TEST

START_TEST(test_oidc_ciba_poll_expiration_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  char * auth_req_id;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_POLL,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, auth_req_id = o_strdup(json_string_value(json_object_get(j_body, "auth_req_id"))));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_body);

  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_POLL,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", auth_req_id,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("authorization_pending", json_string_value(json_object_get(j_body, "error")));
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  sleep(2);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_ID_POLL,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "urn:openid:params:grant-type:ciba",
                                                       U_OPT_POST_BODY_PARAMETER, "auth_req_id", auth_req_id,
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(400, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("expired_token", json_string_value(json_object_get(j_body, "error")));
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  o_free(auth_req_id);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc ciba requests");
  tc_core = tcase_create("test_oidc_ciba_requests");
  tcase_add_test(tc_core, test_oidc_ciba_add_client_poll);
  tcase_add_test(tc_core, test_oidc_ciba_add_client_ping);
  tcase_add_test(tc_core, test_oidc_ciba_add_client_push);
  tcase_add_test(tc_core, test_oidc_ciba_add_plugin_user_code_no_email_no);
  tcase_add_test(tc_core, test_oidc_ciba_client_grant_scopes);
  tcase_add_test(tc_core, test_oidc_ciba_request_client_notification_token_missing);
  tcase_add_test(tc_core, test_oidc_ciba_request_client_notification_token_invalid_chars);
  tcase_add_test(tc_core, test_oidc_ciba_request_client_notification_token_invalid_small_length);
  tcase_add_test(tc_core, test_oidc_ciba_request_client_notification_token_invalid_large_length);
  tcase_add_test(tc_core, test_oidc_ciba_request_login_hint_missing);
  tcase_add_test(tc_core, test_oidc_ciba_request_login_hint_invalid);
  tcase_add_test(tc_core, test_oidc_ciba_request_login_hint_error_key);
  tcase_add_test(tc_core, test_oidc_ciba_request_login_hint_error_format);
  tcase_add_test(tc_core, test_oidc_ciba_request_login_hint_ok);
  tcase_add_test(tc_core, test_oidc_ciba_request_id_token_hint_invalid);
  tcase_add_test(tc_core, test_oidc_ciba_request_id_token_hint_ok);
  tcase_add_test(tc_core, test_oidc_ciba_request_login_hint_token_invalid_signature);
  tcase_add_test(tc_core, test_oidc_ciba_request_login_hint_token_ok);
  tcase_add_test(tc_core, test_oidc_ciba_request_login_hint_too_much);
  tcase_add_test(tc_core, test_oidc_ciba_signed_request_login_hint_invalid_signature);
  tcase_add_test(tc_core, test_oidc_ciba_signed_request_login_hint_replay_jti);
  tcase_add_test(tc_core, test_oidc_ciba_signed_request_login_hint_invalid_aud);
  tcase_add_test(tc_core, test_oidc_ciba_signed_request_login_hint_invalid_iss);
  tcase_add_test(tc_core, test_oidc_ciba_signed_request_login_hint_ok);
  tcase_add_test(tc_core, test_oidc_ciba_client_assertion_request_login_hint_invalid_signature);
  tcase_add_test(tc_core, test_oidc_ciba_client_assertion_request_login_hint_invalid_aud);
  tcase_add_test(tc_core, test_oidc_ciba_client_assertion_request_login_hint_ok);
  tcase_add_test(tc_core, test_oidc_ciba_user_list);
  tcase_add_test(tc_core, test_oidc_ciba_user_check);
  tcase_add_test(tc_core, test_oidc_ciba_user_check_accept);
  tcase_add_test(tc_core, test_oidc_ciba_poll_ok);
  tcase_add_test(tc_core, test_oidc_ciba_ping_ok);
  tcase_add_test(tc_core, test_oidc_ciba_push_ok);
  tcase_add_test(tc_core, test_oidc_ciba_poll_reduced_scope_ok);
  tcase_add_test(tc_core, test_oidc_ciba_push_reduced_scope_ok);
  tcase_add_test(tc_core, test_oidc_ciba_delete_plugin);
  tcase_add_test(tc_core, test_oidc_ciba_add_plugin_user_code_email_no);
  tcase_add_test(tc_core, test_oidc_ciba_request_user_code_invalid);
  tcase_add_test(tc_core, test_oidc_ciba_request_user_code_ok);
  tcase_add_test(tc_core, test_oidc_ciba_delete_plugin);
  tcase_add_test(tc_core, test_oidc_ciba_add_plugin_user_code_no_email);
  tcase_add_test(tc_core, test_oidc_ciba_request_email_ok);
  tcase_add_test(tc_core, test_oidc_ciba_delete_plugin);
  tcase_add_test(tc_core, test_oidc_ciba_add_plugin_expires_soon);
  tcase_add_test(tc_core, test_oidc_ciba_poll_expiration_ok);
  tcase_add_test(tc_core, test_oidc_ciba_delete_plugin);
  tcase_add_test(tc_core, test_oidc_ciba_client_grant_none);
  tcase_add_test(tc_core, test_oidc_ciba_delete_client_poll);
  tcase_add_test(tc_core, test_oidc_ciba_delete_client_ping);
  tcase_add_test(tc_core, test_oidc_ciba_delete_client_push);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, scope_req;
  struct _u_response auth_resp, scope_resp;
  int res, do_test = 0;
  char * cookie;
  json_t * j_body;

  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");

  ulfius_init_request(&admin_req);
  ulfius_init_request(&user_req);

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&scope_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_response(&scope_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    if (auth_resp.nb_cookies) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Admin %s authenticated", ADMIN_USERNAME);
      cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
      do_test = 1;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication admin");
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  if (do_test) {
    // Getting a valid session id for authenticated http requests
    ulfius_init_request(&auth_req);
    ulfius_init_response(&auth_resp);
    auth_req.http_verb = strdup("POST");
    auth_req.http_url = msprintf(SERVER_URI "/auth/");
    j_body = json_pack("{ssss}", "username", USER_USERNAME, "password", USER_PASSWORD);
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200) {
      if (auth_resp.nb_cookies) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", USER_USERNAME);
        cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
        u_map_put(scope_req.map_header, "Cookie", cookie);
        u_map_put(user_req.map_header, "Cookie", cookie);
        o_free(cookie);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication user");
      do_test = 0;
    }

    j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_true());
    run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
    json_decref(j_body);
    
    j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_true());
    run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
    json_decref(j_body);
    
    j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
    run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
    json_decref(j_body);
    
    j_body = json_pack("{sssssss{ss}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "code", "42");
    run_simple_test(&user_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
    json_decref(j_body);
    
    j_body = json_pack("{sssssss{ss}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "code", "88");
    run_simple_test(&user_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
    json_decref(j_body);
    
    j_body = json_pack("{sssssss{ss}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "code", "95");
    run_simple_test(&user_req, "POST", SERVER_URI "/auth/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
    json_decref(j_body);
    
    ulfius_clean_response(&auth_resp);
    ulfius_clean_request(&auth_req);
  }

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_false());
    run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
    json_decref(j_body);
    
    j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_false());
    run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
    json_decref(j_body);
    
    j_body = json_pack("{sssssss{so}}", "username", USER_USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_false());
    run_simple_test(&user_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL);
    json_decref(j_body);
  }

  run_simple_test(&user_req, "DELETE", SERVER_URI "/auth/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);

  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&scope_req);
  ulfius_clean_response(&scope_resp);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
