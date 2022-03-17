/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <check.h>

#include <orcania.h>
#include <yder.h>
#include <ulfius.h>
#include <rhonabwy.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define ISS "https://glewlwyd.tld"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "user1"
#define USER_PASSWORD "password"
#define PLUGIN_NAME "oidc_fapi"
#define PLUGIN_JWT_TYPE_RSA "rsa"
#define PLUGIN_JWT_KEY_SIZE "256"
#define SCOPE_LIST "openid"
#define CLIENT_ID "client1_id"
#define CLIENT_PUBKEY_ID "client_fapi"
#define CLIENT_PUBKEY_PARAM "pubkey"
#define CLIENT_JWKS_PARAM "jwks"
#define CLIENT_JWKS_URI_PARAM "jwks_uri"
#define CLIENT_PUBKEY_NAME "client with pubkey"
#define CLIENT_PUBKEY_REDIRECT "https://glewlwyd.local/"
#define CLIENT_PUBKEY_REDIRECT_ESCAPED "https%3A%2F%2Fglewlwyd.local%2F"
#define CLIENT_SECRET "password"
#define CLIENT_REDIRECT_URI "../../test-oidc.html?param=client1_cb1"
#define CLIENT_REDIRECT_URI_ENCODED "..%2F..%2Ftest-oidc.html%3Fparam%3Dclient1_cb1"
#define CLIENT_SIGN_ALG "PS256"
#define CLIENT_ENC_ALG "RSA-OAEP-256"
#define CLIENT_ENC_ALG_INVALID "RSA1_5"
#define CLIENT_ENC "A128GCM"
#define RESPONSE_TYPE_CODE "code"
#define RESPONSE_TYPE_CODE_ID_TOKEN "code+id_token"
#define RESPONSE_TYPE_CODE_ID_TOKEN_POST "code id_token"
#define STATE "Ohana means family. Family means nobody gets left behind or forgotten"
#define REQUEST_MAX_EXP 120
#define KID "multiple"
#define PLUGIN_CIBA_DEFAULT_EXPIRATION 600
#define PLUGIN_CIBA_MAXIMUM_EXPIRATION 1200
#define CIBA_CLIENT_NOTIFICATION_TOKEN "ZBMDEshXMWMv8KUbBSUnbRgEYpvM8LyA"

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
const char jwk_pubkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"sig\",\"kid\":\""KID"\",\"alg\":\"ES384\"}";
const char jwk_pubkey_ecdsa_str_invalid_alg[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"use\":\"sig\",\"kid\":\""KID"\",\"alg\":\"ES512\"}";
const char jwk_privkey_ecdsa_str[] = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\","\
                                     "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\","\
                                     "\"use\":\"sig\",\"kid\":\""KID"\",\"alg\":\"ES384\"}";
const char jwk_pubkey_ecdsa_str_2[] = "{\"kty\":\"EC\",\"x\":\"RKL0w34ppc4wuBuzotuWo9d6hGv59uWjgc5oimWQtYU\",\"y\":\"S8EabLKBmyT2v_vPSrpfWnYw6edRm9I60UQlbvSS1eU\""\
                                      ",\"d\":\"KMRJaGpxVer0w9lMjIY_UrjC067tZdEJkL5eaiBVWi8\",\"crv\":\"P-256\",\"kid\":\""KID"\",\"alg\":\"ES256\",\"use\":\"sig\"}";
const char jwk_privkey_ecdsa_str_2[] = "{\"kty\":\"EC\",\"x\":\"RKL0w34ppc4wuBuzotuWo9d6hGv59uWjgc5oimWQtYU\",\"y\":\"S8EabLKBmyT2v_vPSrpfWnYw6edRm9I60UQlbvSS1eU\","\
                                       "\"crv\":\"P-256\",\"kid\":\""KID"\",\"alg\":\"ES256\",\"use\":\"sig\"}";
const char jwk_pubkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRX"\
                                  "jBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6"\
                                  "qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\""\
                                  ",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\""KID"\",\"use\":\"sig\"}";
const char jwk_privkey_rsa_str[] = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKR"\
                                   "XjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHz"\
                                   "u6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKg"\
                                   "w\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2v"\
                                   "v7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk"\
                                   "5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoA"\
                                   "C8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7"\
                                   "XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3v"\
                                   "obLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelx"\
                                   "k\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA7"\
                                   "7Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA"\
                                   "6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cg"\
                                   "k\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_m"\
                                   "HZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\""KID"\",\"use\":\"sig\"}";

struct _u_request admin_req;
struct _u_request user_req;

START_TEST(test_oidc_fapi_add_plugin)
{
  json_t * j_param = json_pack("{sssssss{sssssssssssisisisosososososososososososissssss sosisisosososososo}}",
                                "module", "oidc",
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", ISS,
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
                                  "auth-type-code-revoke-replayed", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-id-token-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "oauth-fapi-check-all", json_true(),
                                  "encrypt-out-token-allow", json_true(),
                                  "request-maximum-exp", REQUEST_MAX_EXP,
                                  "client-pubkey-parameter", CLIENT_PUBKEY_PARAM,
                                  "client-jwks-parameter", CLIENT_JWKS_PARAM,
                                  "client-jwks_uri-parameter", CLIENT_JWKS_URI_PARAM,
                                  
                                  "oauth-ciba-allowed", json_true(),
                                  "oauth-ciba-default-expiry", PLUGIN_CIBA_DEFAULT_EXPIRATION,
                                  "oauth-ciba-maximum-expiry", PLUGIN_CIBA_MAXIMUM_EXPIRATION,
                                  "oauth-ciba-mode-poll-allowed", json_true(),
                                  "oauth-ciba-mode-ping-allowed", json_true(),
                                  "oauth-ciba-mode-push-allowed", json_true(),
                                  "oauth-ciba-allow-https-non-secure", json_true(),
                                  "oauth-ciba-user-code-allowed", json_false(),
                                  "oauth-ciba-email-allowed", json_false());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_fapi_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_fapi_add_client_pubkey)
{
  json_t * j_client = json_pack("{ss ss so s[s] s[ssss] s[s] ss ss ss ss so}",
                                "client_id", CLIENT_PUBKEY_ID,
                                "name", CLIENT_PUBKEY_NAME,
                                "confidential", json_true(),
                                "redirect_uri",
                                  CLIENT_PUBKEY_REDIRECT,
                                "authorization_type",
                                  "code", "token", "id_token", "client_credentials",
                                "scope",
                                  SCOPE_LIST,
                                CLIENT_PUBKEY_PARAM, pubkey_1_pem,
                                "authorization_signed_response_alg", CLIENT_SIGN_ALG,
                                "authorization_encrypted_response_alg", CLIENT_ENC_ALG,
                                "authorization_encrypted_response_enc", CLIENT_ENC,
                                "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_fapi_add_client_jwks)
{
  jwks_t * jwks = r_jwks_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str, R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str_2, R_IMPORT_JSON_STR, jwk_pubkey_rsa_str, R_IMPORT_NONE);
  json_t * j_client = json_pack("{ss ss so s[s] s[ssss] s[s] so ss ss ss so}",
                                "client_id", CLIENT_PUBKEY_ID,
                                "name", CLIENT_PUBKEY_NAME,
                                "confidential", json_true(),
                                "redirect_uri",
                                  CLIENT_PUBKEY_REDIRECT,
                                "authorization_type",
                                  "code", "token", "id_token", "client_credentials",
                                "scope",
                                  SCOPE_LIST,
                                CLIENT_JWKS_PARAM, r_jwks_export_to_json_t(jwks),
                                "authorization_signed_response_alg", CLIENT_SIGN_ALG,
                                "authorization_encrypted_response_alg", CLIENT_ENC_ALG,
                                "authorization_encrypted_response_enc", CLIENT_ENC,
                                "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
  r_jwks_free(jwks);
}
END_TEST

START_TEST(test_oidc_fapi_add_client_ciba_poll)
{
  json_t * j_client = json_pack("{ss ss so s[s] s[sssss] s[s] ss ss ss ss ss so}",
                                "client_id", CLIENT_PUBKEY_ID,
                                "name", CLIENT_PUBKEY_NAME,
                                "confidential", json_true(),
                                "redirect_uri",
                                  CLIENT_PUBKEY_REDIRECT,
                                "authorization_type",
                                  "code",
                                  "token",
                                  "id_token",
                                  "client_credentials",
                                  "urn:openid:params:grant-type:ciba",
                                "scope",
                                  SCOPE_LIST,
                                "client_secret", CLIENT_SECRET,
                                "authorization_signed_response_alg", CLIENT_SIGN_ALG,
                                "authorization_encrypted_response_alg", CLIENT_ENC_ALG,
                                "authorization_encrypted_response_enc", CLIENT_ENC,
                                "backchannel_token_delivery_mode", "poll",
                                "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_fapi_add_client_ciba_push)
{
  json_t * j_client = json_pack("{ss ss so s[s] s[sssss] s[s] ss ss ss ss ss so}",
                                "client_id", CLIENT_PUBKEY_ID,
                                "name", CLIENT_PUBKEY_NAME,
                                "confidential", json_true(),
                                "redirect_uri",
                                  CLIENT_PUBKEY_REDIRECT,
                                "authorization_type",
                                  "code",
                                  "token",
                                  "id_token",
                                  "client_credentials",
                                  "urn:openid:params:grant-type:ciba",
                                "scope",
                                  SCOPE_LIST,
                                "client_secret", CLIENT_SECRET,
                                "authorization_signed_response_alg", CLIENT_SIGN_ALG,
                                "authorization_encrypted_response_alg", CLIENT_ENC_ALG,
                                "authorization_encrypted_response_enc", CLIENT_ENC,
                                "backchannel_token_delivery_mode", "push",
                                "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_fapi_add_client_ciba_poll_public)
{
  json_t * j_client = json_pack("{ss ss so s[s] s[sssss] s[s] ss ss ss ss so}",
                                "client_id", CLIENT_PUBKEY_ID,
                                "name", CLIENT_PUBKEY_NAME,
                                "confidential", json_false(),
                                "redirect_uri",
                                  CLIENT_PUBKEY_REDIRECT,
                                "authorization_type",
                                  "code",
                                  "token",
                                  "id_token",
                                  "client_credentials",
                                  "urn:openid:params:grant-type:ciba",
                                "scope",
                                  SCOPE_LIST,
                                "authorization_signed_response_alg", CLIENT_SIGN_ALG,
                                "authorization_encrypted_response_alg", CLIENT_ENC_ALG,
                                "authorization_encrypted_response_enc", CLIENT_ENC,
                                "backchannel_token_delivery_mode", "poll",
                                "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_fapi_add_client_jwks_invalid_alg)
{
  jwks_t * jwks = r_jwks_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str_invalid_alg, R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str_2, R_IMPORT_JSON_STR, jwk_pubkey_rsa_str, R_IMPORT_NONE);
  json_t * j_client = json_pack("{ss ss so s[s] s[ssss] s[s] so ss ss ss so}",
                                "client_id", CLIENT_PUBKEY_ID,
                                "name", CLIENT_PUBKEY_NAME,
                                "confidential", json_true(),
                                "redirect_uri",
                                  CLIENT_PUBKEY_REDIRECT,
                                "authorization_type",
                                  "code", "token", "id_token", "client_credentials",
                                "scope",
                                  SCOPE_LIST,
                                CLIENT_JWKS_PARAM, r_jwks_export_to_json_t(jwks),
                                "authorization_signed_response_alg", CLIENT_SIGN_ALG,
                                "authorization_encrypted_response_alg", CLIENT_ENC_ALG,
                                "authorization_encrypted_response_enc", CLIENT_ENC,
                                "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
  r_jwks_free(jwks);
}
END_TEST

START_TEST(test_oidc_fapi_add_client_jwks_enc_alg_invalid)
{
  jwks_t * jwks = r_jwks_quick_import(R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str, R_IMPORT_JSON_STR, jwk_pubkey_ecdsa_str_2, R_IMPORT_JSON_STR, jwk_pubkey_rsa_str, R_IMPORT_NONE);
  json_t * j_client = json_pack("{ss ss so s[s] s[ssss] s[s] so ss ss ss so}",
                                "client_id", CLIENT_PUBKEY_ID,
                                "name", CLIENT_PUBKEY_NAME,
                                "confidential", json_true(),
                                "redirect_uri",
                                  CLIENT_PUBKEY_REDIRECT,
                                "authorization_type",
                                  "code", "token", "id_token", "client_credentials",
                                "scope",
                                  SCOPE_LIST,
                                CLIENT_JWKS_PARAM, r_jwks_export_to_json_t(jwks),
                                "authorization_signed_response_alg", CLIENT_SIGN_ALG,
                                "authorization_encrypted_response_alg", CLIENT_ENC_ALG_INVALID,
                                "authorization_encrypted_response_enc", CLIENT_ENC,
                                "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
  r_jwks_free(jwks);
}
END_TEST

START_TEST(test_oidc_fapi_delete_client)
{
  json_t * j_param = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_PUBKEY_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_fapi_id_token_state_valid)
{
  struct _u_request req;
  struct _u_response resp, resp2;
  char * id_token, * code, s_hash[33], s_hash_encoded[64];
  size_t s_hash_len = 33, s_hash_encoded_len = 0;
  gnutls_datum_t s_data;
  jwt_t * jwt;
  int alg = GNUTLS_DIG_UNKNOWN;
  json_t * j_body;

  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=%s&g_continue&client_id=%s&redirect_uri=%s&state=%s&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, RESPONSE_TYPE_CODE_ID_TOKEN, CLIENT_ID, CLIENT_REDIRECT_URI_ENCODED, STATE, SCOPE_LIST);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  id_token = o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token=");
  if (o_strchr(id_token, '&') != NULL) {
    *o_strchr(id_token, '&') = '\0';
  }
  code = o_strstr(u_map_get(resp.map_header, "Location"), "code=") + o_strlen("code=");
  if (o_strchr(code, '&') != NULL) {
    *o_strchr(code, '&') = '\0';
  }
  
  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(id_token, R_IMPORT_NONE, 0));
  ck_assert_ptr_ne(r_jwt_get_claim_str_value(jwt, "s_hash"), NULL);

  switch (r_jwt_get_sign_alg(jwt)) {
    case R_JWA_ALG_HS256:
    case R_JWA_ALG_RS256:
    case R_JWA_ALG_ES256:
    case R_JWA_ALG_PS256:
    case R_JWA_ALG_EDDSA:
    case R_JWA_ALG_ES256K:
      alg = GNUTLS_DIG_SHA256;
      break;
    case R_JWA_ALG_HS384:
    case R_JWA_ALG_RS384:
    case R_JWA_ALG_ES384:
    case R_JWA_ALG_PS384:
      alg = GNUTLS_DIG_SHA384;
      break;
    case R_JWA_ALG_HS512:
    case R_JWA_ALG_RS512:
    case R_JWA_ALG_ES512:
    case R_JWA_ALG_PS512:
      alg = GNUTLS_DIG_SHA384;
      break;
    default:
      alg = GNUTLS_DIG_UNKNOWN;
      break;
  }
  s_data.data = (unsigned char *)STATE;
  s_data.size = o_strlen(STATE);
  ck_assert_int_eq(gnutls_fingerprint(alg, &s_data, s_hash, &s_hash_len), GNUTLS_E_SUCCESS);
  ck_assert_int_eq(o_base64url_encode((unsigned char *)s_hash, s_hash_len/2, (unsigned char *)s_hash_encoded, &s_hash_encoded_len), 1);
  s_hash_encoded[s_hash_encoded_len] = '\0';

  ck_assert_str_eq(s_hash_encoded, r_jwt_get_claim_str_value(jwt, "s_hash"));

  r_jwt_free(jwt);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp2);
  ck_assert_int_eq(U_OK, ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/token",
                                                       U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                                       U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_ID,
                                                       U_OPT_POST_BODY_PARAMETER, "redirect_uri", CLIENT_REDIRECT_URI,
                                                       U_OPT_POST_BODY_PARAMETER, "code", code,
                                                       U_OPT_NONE));
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp2), U_OK);
  ck_assert_int_eq(200, resp2.status);
  ck_assert_ptr_ne((j_body = ulfius_get_json_body_response(&resp2, NULL)), NULL);
  ck_assert_ptr_ne(json_object_get(j_body, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_body, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_body, "id_token"), NULL);

  ck_assert_ptr_ne(NULL, jwt = r_jwt_quick_parse(json_string_value(json_object_get(j_body, "id_token")), R_IMPORT_NONE, 0));
  ck_assert_ptr_ne(r_jwt_get_claim_str_value(jwt, "s_hash"), NULL);

  switch (r_jwt_get_sign_alg(jwt)) {
    case R_JWA_ALG_HS256:
    case R_JWA_ALG_RS256:
    case R_JWA_ALG_ES256:
    case R_JWA_ALG_PS256:
    case R_JWA_ALG_EDDSA:
    case R_JWA_ALG_ES256K:
      alg = GNUTLS_DIG_SHA256;
      break;
    case R_JWA_ALG_HS384:
    case R_JWA_ALG_RS384:
    case R_JWA_ALG_ES384:
    case R_JWA_ALG_PS384:
      alg = GNUTLS_DIG_SHA384;
      break;
    case R_JWA_ALG_HS512:
    case R_JWA_ALG_RS512:
    case R_JWA_ALG_ES512:
    case R_JWA_ALG_PS512:
      alg = GNUTLS_DIG_SHA384;
      break;
    default:
      alg = GNUTLS_DIG_UNKNOWN;
      break;
  }
  s_data.data = (unsigned char *)STATE;
  s_data.size = o_strlen(STATE);
  ck_assert_int_eq(gnutls_fingerprint(alg, &s_data, s_hash, &s_hash_len), GNUTLS_E_SUCCESS);
  ck_assert_int_eq(o_base64url_encode((unsigned char *)s_hash, s_hash_len/2, (unsigned char *)s_hash_encoded, &s_hash_encoded_len), 1);
  s_hash_encoded[s_hash_encoded_len] = '\0';

  ck_assert_str_eq(s_hash_encoded, r_jwt_get_claim_str_value(jwt, "s_hash"));

  json_decref(j_body);
  ulfius_clean_response(&resp);
  ulfius_clean_response(&resp2);
  ulfius_clean_request(&req);
  r_jwt_free(jwt);
}
END_TEST

START_TEST(test_oidc_fapi_request_jwt_response_ok)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  r_jwt_init(&jwt_request);
  time_t now;
  
  time(&now);
  ck_assert_ptr_ne(jwt_request, NULL);
  r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256);
  r_jwt_add_sign_keys_pem_der(jwt_request, R_FORMAT_PEM, (const unsigned char *)privkey_1_pem, sizeof(privkey_1_pem), NULL, 0);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE_CODE_ID_TOKEN_POST);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_int_value(jwt_request, "nbf", now);
  r_jwt_set_claim_int_value(jwt_request, "exp", now+60);
  r_jwt_set_claim_str_value(jwt_request, "state", STATE);
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "id_token="), 1);
  
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_fapi_request_jwt_exp_invalid)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  r_jwt_init(&jwt_request);
  time_t now;
  
  time(&now);
  ck_assert_ptr_ne(jwt_request, NULL);
  r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256);
  r_jwt_add_sign_keys_pem_der(jwt_request, R_FORMAT_PEM, (const unsigned char *)privkey_1_pem, sizeof(privkey_1_pem), NULL, 0);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE_CODE_ID_TOKEN_POST);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_int_value(jwt_request, "nbf", now-60);
  r_jwt_set_claim_int_value(jwt_request, "exp", now-30);
  r_jwt_set_claim_str_value(jwt_request, "state", STATE);
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_fapi_request_jwt_nbf_invalid)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  r_jwt_init(&jwt_request);
  time_t now;
  
  time(&now);
  ck_assert_ptr_ne(jwt_request, NULL);
  r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256);
  r_jwt_add_sign_keys_pem_der(jwt_request, R_FORMAT_PEM, (const unsigned char *)privkey_1_pem, sizeof(privkey_1_pem), NULL, 0);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE_CODE_ID_TOKEN_POST);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_int_value(jwt_request, "nbf", now+10);
  r_jwt_set_claim_int_value(jwt_request, "exp", now+30);
  r_jwt_set_claim_str_value(jwt_request, "state", STATE);
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_fapi_request_jwt_nbf_too_long)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  r_jwt_init(&jwt_request);
  time_t now;
  
  time(&now);
  ck_assert_ptr_ne(jwt_request, NULL);
  r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256);
  r_jwt_add_sign_keys_pem_der(jwt_request, R_FORMAT_PEM, (const unsigned char *)privkey_1_pem, sizeof(privkey_1_pem), NULL, 0);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE_CODE_ID_TOKEN_POST);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_int_value(jwt_request, "nbf", now);
  r_jwt_set_claim_int_value(jwt_request, "exp", now+(REQUEST_MAX_EXP*2));
  r_jwt_set_claim_str_value(jwt_request, "state", STATE);
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_fapi_request_jwt_nbf_missing)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  r_jwt_init(&jwt_request);
  time_t now;
  
  time(&now);
  ck_assert_ptr_ne(jwt_request, NULL);
  r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256);
  r_jwt_add_sign_keys_pem_der(jwt_request, R_FORMAT_PEM, (const unsigned char *)privkey_1_pem, sizeof(privkey_1_pem), NULL, 0);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE_CODE_ID_TOKEN_POST);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_int_value(jwt_request, "exp", now+(REQUEST_MAX_EXP*2));
  r_jwt_set_claim_str_value(jwt_request, "state", STATE);
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_fapi_request_jwt_exp_missing)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  r_jwt_init(&jwt_request);
  time_t now;
  
  time(&now);
  ck_assert_ptr_ne(jwt_request, NULL);
  r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256);
  r_jwt_add_sign_keys_pem_der(jwt_request, R_FORMAT_PEM, (const unsigned char *)privkey_1_pem, sizeof(privkey_1_pem), NULL, 0);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE_CODE_ID_TOKEN_POST);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_int_value(jwt_request, "nbf", now);
  r_jwt_set_claim_str_value(jwt_request, "state", STATE);
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_fapi_request_jwt_multiple_kid_response_ok)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  r_jwt_init(&jwt_request);
  time_t now;
  
  time(&now);
  ck_assert_ptr_ne(jwt_request, NULL);
  r_jwt_add_sign_keys_json_str(jwt_request, jwk_privkey_ecdsa_str, NULL);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE_CODE_ID_TOKEN_POST);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_int_value(jwt_request, "nbf", now);
  r_jwt_set_claim_int_value(jwt_request, "exp", now+60);
  r_jwt_set_claim_str_value(jwt_request, "state", STATE);
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "id_token="), 1);
  
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_fapi_request_jwt_multiple_kid_invalid_alg)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  r_jwt_init(&jwt_request);
  time_t now;
  
  time(&now);
  ck_assert_ptr_ne(jwt_request, NULL);
  r_jwt_add_sign_keys_json_str(jwt_request, jwk_privkey_ecdsa_str, NULL);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE_CODE_ID_TOKEN_POST);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_int_value(jwt_request, "nbf", now);
  r_jwt_set_claim_int_value(jwt_request, "exp", now+60);
  r_jwt_set_claim_str_value(jwt_request, "state", STATE);
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_fapi_response_jwt_enc_ok)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  r_jwt_init(&jwt_request);
  time_t now;
  
  time(&now);
  ck_assert_ptr_ne(jwt_request, NULL);
  r_jwt_add_sign_keys_json_str(jwt_request, jwk_privkey_ecdsa_str, NULL);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE_CODE_ID_TOKEN_POST);
  r_jwt_set_claim_str_value(jwt_request, "response_mode", "query.jwt");
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_int_value(jwt_request, "nbf", now);
  r_jwt_set_claim_int_value(jwt_request, "exp", now+60);
  r_jwt_set_claim_str_value(jwt_request, "state", STATE);
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "response="), 1);
  
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_fapi_response_jwt_enc_error)
{
  jwt_t * jwt_request = NULL;
  char * url, * request;
  r_jwt_init(&jwt_request);
  time_t now;
  
  time(&now);
  ck_assert_ptr_ne(jwt_request, NULL);
  r_jwt_add_sign_keys_json_str(jwt_request, jwk_privkey_ecdsa_str, NULL);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE_CODE_ID_TOKEN_POST);
  r_jwt_set_claim_str_value(jwt_request, "response_mode", "jwt");
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_int_value(jwt_request, "nbf", now);
  r_jwt_set_claim_int_value(jwt_request, "exp", now+60);
  r_jwt_set_claim_str_value(jwt_request, "state", STATE);
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  request = r_jwt_serialize_signed(jwt_request, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  url = msprintf("%s/%s/auth?g_continue&request=%s", SERVER_URI, PLUGIN_NAME, request);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "error="), 1);
  
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_fapi_ciba_request_ok)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_PUBKEY_ID,
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

START_TEST(test_oidc_fapi_ciba_request_invalid_delivery_mode)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_AUTH_BASIC_USER, CLIENT_PUBKEY_ID,
                                                       U_OPT_AUTH_BASIC_PASSWORD, CLIENT_SECRET,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(401, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_client", json_string_value(json_object_get(j_body, "error")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_fapi_ciba_request_invalid_client_public)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_body;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/ciba",
                                                       U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT_PUBKEY_ID,
                                                       U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                                       U_OPT_POST_BODY_PARAMETER, "client_notification_token", CIBA_CLIENT_NOTIFICATION_TOKEN,
                                                       U_OPT_POST_BODY_PARAMETER, "login_hint", "{\"username\":\""USER_USERNAME"\"}",
                                                       U_OPT_NONE), U_OK);
  ck_assert_int_eq(U_OK, ulfius_send_http_request(&req, &resp));
  ck_assert_int_eq(401, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_str_eq("invalid_client", json_string_value(json_object_get(j_body, "error")));
  
  json_decref(j_body);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc fapi");
  tc_core = tcase_create("test_oidc_fapi");
  tcase_add_test(tc_core, test_oidc_fapi_add_plugin);
  tcase_add_test(tc_core, test_oidc_fapi_add_client_pubkey);
  tcase_add_test(tc_core, test_oidc_fapi_id_token_state_valid);
  tcase_add_test(tc_core, test_oidc_fapi_request_jwt_response_ok);
  tcase_add_test(tc_core, test_oidc_fapi_request_jwt_exp_invalid);
  tcase_add_test(tc_core, test_oidc_fapi_request_jwt_nbf_invalid);
  tcase_add_test(tc_core, test_oidc_fapi_request_jwt_nbf_too_long);
  tcase_add_test(tc_core, test_oidc_fapi_request_jwt_nbf_missing);
  tcase_add_test(tc_core, test_oidc_fapi_request_jwt_exp_missing);
  tcase_add_test(tc_core, test_oidc_fapi_delete_client);
  tcase_add_test(tc_core, test_oidc_fapi_add_client_jwks);
  tcase_add_test(tc_core, test_oidc_fapi_response_jwt_enc_ok);
  tcase_add_test(tc_core, test_oidc_fapi_request_jwt_multiple_kid_response_ok);
  tcase_add_test(tc_core, test_oidc_fapi_delete_client);
  tcase_add_test(tc_core, test_oidc_fapi_add_client_jwks_invalid_alg);
  tcase_add_test(tc_core, test_oidc_fapi_request_jwt_multiple_kid_invalid_alg);
  tcase_add_test(tc_core, test_oidc_fapi_delete_client);
  tcase_add_test(tc_core, test_oidc_fapi_add_client_jwks_enc_alg_invalid);
  tcase_add_test(tc_core, test_oidc_fapi_response_jwt_enc_error);
  tcase_add_test(tc_core, test_oidc_fapi_delete_client);
  tcase_add_test(tc_core, test_oidc_fapi_add_client_ciba_poll);
  tcase_add_test(tc_core, test_oidc_fapi_ciba_request_ok);
  tcase_add_test(tc_core, test_oidc_fapi_delete_client);
  tcase_add_test(tc_core, test_oidc_fapi_add_client_ciba_push);
  tcase_add_test(tc_core, test_oidc_fapi_ciba_request_invalid_delivery_mode);
  tcase_add_test(tc_core, test_oidc_fapi_delete_client);
  tcase_add_test(tc_core, test_oidc_fapi_add_client_ciba_poll_public);
  tcase_add_test(tc_core, test_oidc_fapi_ciba_request_invalid_client_public);
  tcase_add_test(tc_core, test_oidc_fapi_delete_client);
  tcase_add_test(tc_core, test_oidc_fapi_delete_plugin);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req;
  struct _u_response auth_resp;
  int res, do_test = 0;
  json_t * j_body;
  char * cookie;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  ulfius_init_request(&admin_req);
  ulfius_init_request(&user_req);

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
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
    auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
    j_body = json_pack("{ssss}", "username", USER_USERNAME, "password", USER_PASSWORD);
    ulfius_set_json_body_request(&auth_req, j_body);
    json_decref(j_body);
    res = ulfius_send_http_request(&auth_req, &auth_resp);
    if (res == U_OK && auth_resp.status == 200) {
      if (auth_resp.nb_cookies) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "User %s authenticated", USER_USERNAME);
        cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
        u_map_put(user_req.map_header, "Cookie", cookie);
        o_free(cookie);
      } else {
        do_test = 0;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication user");
      do_test = 0;
    }
    ulfius_clean_response(&auth_resp);
    ulfius_clean_request(&auth_req);
  }
  
  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }
  
  run_simple_test(&user_req, "DELETE", SERVER_URI "/auth/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  y_close_logs();
  
  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
