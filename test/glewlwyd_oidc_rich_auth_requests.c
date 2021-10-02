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
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define USER_USERNAME "user1"
#define USER_PASSWORD "password"
#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "oidc_rar"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_JWT_TYPE_RSA "rsa"
#define PLUGIN_JWT_KEY_SIZE "256"
#define SCOPE_LIST "g_profile openid"
#define SCOPE_1 "g_profile"
#define SCOPE_2 "openid"
#define SCOPE_3 "g_admin"
#define CLIENT "client3_id"
#define CLIENT_PASSWORD "password"
#define RESPONSE_TYPE "code token"
#define RAR1 "type1"
#define RAR2 "type2"
#define RAR3 "type3"
#define RAR4 "type4"
#define ENRICHED1 "name"
#define ENRICHED2 "email"
#define PRIVILEGE1 "read"
#define PRIVILEGE2 "write"
#define CLIENT_PUBKEY_ID "client_rar"
#define CLIENT_SECRET "secret_string"
#define CLIENT_AUTH_TOKEN_MAX_AGE 3600
#define CLIENT_PUBKEY_PARAM "pubkey"
#define CLIENT_PUBKEY_NAME "client with pubkey"
#define CLIENT_PUBKEY_REDIRECT "https://glewlwyd.local/"
#define CLIENT_PUBKEY_REDIRECT_ESCAPED "https%3A%2F%2Fglewlwyd.local%2F"
#define CLIENT_SCOPE "scope1"
#define KID_PUB "pubkey"
#define CLIENT_JWKS_PARAM "jwks"
#define CLIENT_JWKS_URI_PARAM "jwks_uri"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600

const char pubkey_1_jwk[] = "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AMWhdXoJpkPtPwABHL_yXUwgcYuwNOVbw70YGmMzhFqiRd6r92-onw-BOAvfnIq-rSMgjidllxOE1fXwlgUIyKJmnHUI3RMDABFmGFRM-Dz6VmQxHgiioLM-Q5yzcj85zIqJvNrw0RL0qhvssQBG5Fta_jLXBUXeGEmciWA0lSfrdlS-zbfxsWqPzAvKyT_0B80m1o8K7ksFtyTPu-cHbCVGx4ciGeZUNrtOnevGQPUOE-tIvsxOPcqC3fPjyI3K4TN5GCCZHEyso1qmRFfsHtenq6EvD1_2DebcODnfnym-iNFyC4YsgqipToNxR3WPIgCu-WrSOk71-93ovs0hd1MhBYw03J4Xupjxy_URCFZm9Pp-9H3j_0hUKmhUWmpsQTpAT7FWvTT-MyyYkZ-9Y33-6KR3E-82kdfXIoEMbGJnfq2Z4Yh_lF3pfD-5FUzOzgnOy0UiTxusWOBbaVhNqmm6xmlHwQjBrax9Bqo7WzQpwXgXgooo6TeVz6pxpUl6V63d5o5XZaxYYilUpZ78qXpHQMwNFr6a2gct-dU8zLF6YaJHIaMp6XT9OD8r-w7SOkq1O7J-UGRqGbUVczYzhApY1Q-B2ZnO18P5KQnG97AbU_Sjk5Rnf6HJ-w-E8NOIwgo5jzloV_5Ck6w-DH_sL5FDca89BGuzwpQEH_h3ma43\",\"e\":\"AQAB\",\"kid\":\"" KID_PUB "\"}]}";
const char privkey_1_jwk[] = "{\"kty\":\"RSA\",\"n\":\"AMWhdXoJpkPtPwABHL_yXUwgcYuwNOVbw70YGmMzhFqiRd6r92-onw-BOAvfnIq-rSMgjidllxOE1fXwlgUIyKJmnHUI3RMDABFmGFRM-Dz6VmQxHgiioLM-Q5yzcj85zIqJvNrw0RL0qhvssQBG5Fta_jLXBUXeGEmciWA0lSfrdlS-zbfxsWqPzAvKyT_0B80m1o8K7ksFtyTPu-cHbCVGx4ciGeZUNrtOnevGQPUOE-tIvsxOPcqC3fPjyI3K4TN5GCCZHEyso1qmRFfsHtenq6EvD1_2DebcODnfnym-iNFyC4YsgqipToNxR3WPIgCu-WrSOk71-93ovs0hd1MhBYw03J4Xupjxy_URCFZm9Pp-9H3j_0hUKmhUWmpsQTpAT7FWvTT-MyyYkZ-9Y33-6KR3E-82kdfXIoEMbGJnfq2Z4Yh_lF3pfD-5FUzOzgnOy0UiTxusWOBbaVhNqmm6xmlHwQjBrax9Bqo7WzQpwXgXgooo6TeVz6pxpUl6V63d5o5XZaxYYilUpZ78qXpHQMwNFr6a2gct-dU8zLF6YaJHIaMp6XT9OD8r-w7SOkq1O7J-UGRqGbUVczYzhApY1Q-B2ZnO18P5KQnG97AbU_Sjk5Rnf6HJ-w-E8NOIwgo5jzloV_5Ck6w-DH_sL5FDca89BGuzwpQEH_h3ma43\",\"e\":\"AQAB\",\"d\":\"AIiu6F7k-ZcVKHNKUaX3a8tQzPb9gTf3xWKsnuNpJ-q_PG-Ko_EXwBqrFiYwG0ZiJcCbrXVV76zSPGCCal9E-e5H5YGUBcI2Wv-tiroTGcSipslYpxr1zwrozz47ZZKQ2QQfyvvpfdAMYvI5Oxmj7h-4yQJEcCMoPcf7eY-ODnKziP2HkSPdBwVaOpcVQyb2EcczS0VXHAPLCiVtftmD6qnFUA4H6b3BFLFq6BG-5gIWIHSjtUH8AwRiijs5mOVoIWTGJYe2HTpyU_BH-hCM_6_LCQrLT2jg9jBqsoBkRuJKIroolAvSEPOxVNnXqMKHoc6zNVFJ4IXn3rBVXlDlCm69xoe67-X2M4o8LXpdnwFtvao3YYKqAqv1kH0JZE9kJyY3odhXa-SRZpvOCoE3YpDr5UTlRkEWZATQjqtGP7JEq_RQwtDwM1NpANIl4cFAJVhUJbndjMeJqBcA4-NEV6bBjWkenw179H6UuWNXNzXklPsgtMnF_PwcBFKutwnFqHAE5g6w9iHQ5yG7_2m4zModfBiGiSy3cdQ2f3MEHRRoBmqooEGU_6Urrn6iyAFxk_sINEnT_7Emygle_QwP5N-BQuFpD_NWojGirWwOwiWYBHRBXP0ub17bNx7w4gha6CxHnXyJ0MZBayOIMrnQGeWC7o5a932LCTQfegdBh5xh\",\"p\":\"APQQSKxv01Oky-jENQwxiZcpI4a5PzLPFFCgEqIjSRamCzrCQ07e97iqhU1b8IvRwxDtX358pFKAq7tmwpN2QQb1T9fqUwCpeQuMwRsZwoaM7ZcTSj2FZ_2djN1ixQfzqQ21VxkMRbrdyExqCSJXnHMcLeiFmu81dVopV2iwDbUQv4jZe_ktPUTH4HKle48Y0v9pu22lD5cknAQGB1gUNfyJ0PbUxZMITrZDz4khhYgxqvJ7GluYRNv2tezV-bb5leXbSLDrRgTKqcl5ZjkgLm9FRNGZZAmlsCHEeB3nvCs2ePQYDuLgEkNtuu39kpLFJO6j70bjnvpaIAcDVpPmEE8\",\"q\":\"AM9L09Grg2uSrNUGfj9pfpsMn0k5kqV0n3WjX9z5ZLkwLNNrs0SJjb93haO2MPNlyYhctCpPKnfHJKZWaLhFDV6xr-ubf7c3DbBJjPhlV8dUkgmHfIqWDPl6pzN0xC61zC4IE15LgW_JEMpq53fRWnIHdufs-105QO8YOo0CVYKYjqut4hVbYRBSTaeVLb1vj_yhaL0qV7orQoTrpr6Bg20nftBBa-8Md_B5l0QyiSfvOjKnXsjULQdQGbtypQZvu2jUasnUVUQHBgeF5W5WFj8qCGGnmehqY6QissipLoRMcGPaV_gJKisgcorF7sSU_QzcBUmPk377LkzZXGNUYZk\",\"qi\":\"AILHVNisODhO4GC8P709DqGdVdufLZf2Bl7AwjWyYTkpEzEfQCHHUnmOoTCn-OEvnn9lWiaCaTijtlUmos0fCfvSQLk9elciIOmlRk8G1EtnnzYQsTmerLoMJBgQ02hhip8GK47Y7mbZIjaPB625Dv8F4RHd9ZiTzXTGcNc6bldWlNNbbqw9DWS1DORPhdQEPU424qcYvHq_eklFCujWukO8ul3FEZYnTcth2ODSFMb0a0SCuDGkGI8BDI-_4n6-4wIlAXtc8Vt9Ko8WxJjCK_v2Ae9x05eknWZj0JxuyoAjPtJApp0pt25omJwZr_lY5i8T0cL6dDF5nZcA9hN__eo\",\"dp\":\"ALL4hfI9BmCdxhFoX-YTJWw9dJnEmf1uMN12pHNVILGFDVMHRUg-5LT8BkhWFSzSoxJ0nsQoLm95f3Uqw6BS5RhvJx-T603e-K5phumSmD0GduuD77rxavJlZ_ioBwfvu5Yb1kS95RxEqi6uywft6wHWNiv-XUDwmJ-HFVvlTgfqwileIjT04argT0yC4PpsH73AEPs0QRx6chXZPeVu3K_Vd_Co0kEhpGavjy5l8H-QvGSXtRpZrJUIcxu7RSTSHQOzK7jgrjWxT5Q4e6eEW8ioqPByZRNV9rSsV9DGMAwYI9YLFk90NLBRdPQ0MBmEi7KbcEkxfVDkafv6jLBj0q0\",\"dq\":\"AJldyYY7dczVxMcKucbinwfJq-N6E_QTt5JKYDdV0F5utQtqiEQx3MyGejooJkk9yn_3zlfrIElj7cqe7XU_qWeg4L3Y2wHLWnZNxF1WZT4VZMJmGg9SeqDtTNz2C9tfJ4P695FxHX99681GkKAGJPtuaFuo6kQLgu4iJ9eBnZA0nIGJ8VXJuKNhsRBGf4PDEW1gYeRqemNDdEBxNHmHypusd9dOP7OpruccnnyXQwBnrtAhIjBFQldBvPgBFvUPH0GsvqE6VicxZxWTy635RRZQW8kcPfNFGxkpjsqE2OSKxTArL6BT733e0L-5NzD75cho1ASblA2DerriqcbXfCk\",\"kid\":\"" KID_PUB "\"}";
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

START_TEST(test_oidc_rar_add_plugin_unsigned)
{
  json_t * j_param = json_pack("{sssssss{sssssssssisisisosososososososososososssosos{s{s[ss]s[ss]s[ss]s[ss]s[ss]s[s]}s{s[s]s[ss]s[ss]s[ss]s[s]s[s]}s{s[s]s[s]s[s]s[sss]s[s]s[ss]}s{}}}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", "sha",
                                  "jwt-key-size", "256",
                                  "key", "secret_" PLUGIN_NAME,
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
                                  "introspection-revocation-allowed", json_true(),
                                  "introspection-revocation-allow-target-client", json_true(),
                                  "oauth-rar-allowed", json_true(),
                                  "rar-types-client-property", "authorization_data_types",
                                  "rar-allow-auth-unsigned", json_true(),
                                  "rar-allow-auth-unencrypted", json_true(),
                                  "rar-types",
                                    RAR1,
                                      "scopes",
                                        SCOPE_1,
                                        SCOPE_2,
                                      "locations",
                                        "https://"RAR1"-1.resource.tld",
                                        "https://"RAR1"-2.resource.tld",
                                      "actions",
                                        "action1-"RAR1,
                                        "action2-"RAR1,
                                      "datatypes",
                                        "type1-"RAR1,
                                        "type2-"RAR1,
                                      "enriched",
                                        ENRICHED1,
                                        ENRICHED2,
                                      "privileges",
                                        PRIVILEGE1,
                                    RAR2,
                                      "scopes",
                                        SCOPE_1,
                                      "locations",
                                        "https://"RAR2"-1.resource.tld",
                                        "https://"RAR2"-2.resource.tld",
                                      "actions",
                                        "action1-"RAR2,
                                        "action2-"RAR2,
                                      "datatypes",
                                        "type1-"RAR2,
                                        "type2-"RAR2,
                                      "enriched",
                                        ENRICHED1,
                                      "privileges",
                                        PRIVILEGE1,
                                    RAR3,
                                      "scopes",
                                        "g_admin",
                                      "locations",
                                        "https://"RAR3".resource.tld",
                                      "actions",
                                        "action-"RAR3,
                                      "datatypes",
                                        "type1-"RAR3,
                                        "type2-"RAR3,
                                        "type3-"RAR3,
                                      "enriched",
                                        ENRICHED2,
                                      "privileges",
                                        PRIVILEGE1,
                                        PRIVILEGE2,
                                    RAR4);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_rar_add_plugin_signed_unencrypted)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssssisisisososososososososososisssssssosssosos{s{s[ss]s[ss]s[ss]s[ss]s[ss]s[s]}s{s[s]s[ss]s[ss]s[ss]s[s]s[s]}s{s[s]s[s]s[s]s[sss]s[s]s[ss]}s{}}}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", PLUGIN_JWT_TYPE_RSA,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", privkey_2_pem,
                                  "cert", pubkey_2_pem,
                                  "code-duration", PLUGIN_CODE_DURATION,
                                  "refresh-token-duration", PLUGIN_REFRESH_TOKEN_DURATION,
                                  "access-token-duration", PLUGIN_ACCESS_TOKEN_DURATION,
                                  "allow-non-oidc", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-implicit-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "request-parameter-allow", json_true(),
                                  "request-parameter-allow-encrypted", json_true(),
                                  "request-uri-allow-https-non-secure", json_true(),
                                  "request-maximum-exp", CLIENT_AUTH_TOKEN_MAX_AGE,
                                  "client-pubkey-parameter", CLIENT_PUBKEY_PARAM,
                                  "client-jwks-parameter", CLIENT_JWKS_PARAM,
                                  "client-jwks_uri-parameter", CLIENT_JWKS_URI_PARAM,
                                  "oauth-rar-allowed", json_true(),
                                  "rar-types-client-property", "authorization_data_types",
                                  "rar-allow-auth-unsigned", json_false(),
                                  "rar-allow-auth-unencrypted", json_true(),
                                  "rar-types",
                                    RAR1,
                                      "scopes",
                                        SCOPE_1,
                                        SCOPE_2,
                                      "locations",
                                        "https://"RAR1"-1.resource.tld",
                                        "https://"RAR1"-2.resource.tld",
                                      "actions",
                                        "action1-"RAR1,
                                        "action2-"RAR1,
                                      "datatypes",
                                        "type1-"RAR1,
                                        "type2-"RAR1,
                                      "enriched",
                                        ENRICHED1,
                                        ENRICHED2,
                                      "privileges",
                                        PRIVILEGE1,
                                    RAR2,
                                      "scopes",
                                        SCOPE_1,
                                      "locations",
                                        "https://"RAR2"-1.resource.tld",
                                        "https://"RAR2"-2.resource.tld",
                                      "actions",
                                        "action1-"RAR2,
                                        "action2-"RAR2,
                                      "datatypes",
                                        "type1-"RAR2,
                                        "type2-"RAR2,
                                      "enriched",
                                        ENRICHED1,
                                      "privileges",
                                        PRIVILEGE1,
                                    RAR3,
                                      "scopes",
                                        "g_admin",
                                      "locations",
                                        "https://"RAR3".resource.tld",
                                      "actions",
                                        "action-"RAR3,
                                      "datatypes",
                                        "type1-"RAR3,
                                        "type2-"RAR3,
                                        "type3-"RAR3,
                                      "enriched",
                                        ENRICHED2,
                                      "privileges",
                                        PRIVILEGE1,
                                        PRIVILEGE2,
                                    RAR4);

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_rar_add_plugin_signed_encrypted)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssssisisisososososososososososisssssssosssosos{s{s[ss]s[ss]s[ss]s[ss]s[ss]s[s]}s{s[s]s[ss]s[ss]s[ss]s[s]s[s]}s{s[s]s[s]s[s]s[sss]s[s]s[ss]}s{}}}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwt-type", PLUGIN_JWT_TYPE_RSA,
                                  "jwt-key-size", PLUGIN_JWT_KEY_SIZE,
                                  "key", privkey_2_pem,
                                  "cert", pubkey_2_pem,
                                  "code-duration", PLUGIN_CODE_DURATION,
                                  "refresh-token-duration", PLUGIN_REFRESH_TOKEN_DURATION,
                                  "access-token-duration", PLUGIN_ACCESS_TOKEN_DURATION,
                                  "allow-non-oidc", json_true(),
                                  "auth-type-client-enabled", json_true(),
                                  "auth-type-code-enabled", json_true(),
                                  "auth-type-token-enabled", json_true(),
                                  "auth-type-implicit-enabled", json_true(),
                                  "auth-type-password-enabled", json_true(),
                                  "auth-type-refresh-enabled", json_true(),
                                  "request-parameter-allow", json_true(),
                                  "request-parameter-allow-encrypted", json_true(),
                                  "request-uri-allow-https-non-secure", json_true(),
                                  "request-maximum-exp", CLIENT_AUTH_TOKEN_MAX_AGE,
                                  "client-pubkey-parameter", CLIENT_PUBKEY_PARAM,
                                  "client-jwks-parameter", CLIENT_JWKS_PARAM,
                                  "client-jwks_uri-parameter", CLIENT_JWKS_URI_PARAM,
                                  "oauth-rar-allowed", json_true(),
                                  "rar-types-client-property", "authorization_data_types",
                                  "rar-allow-auth-unsigned", json_false(),
                                  "rar-allow-auth-unencrypted", json_false(),
                                  "rar-types",
                                    RAR1,
                                      "scopes",
                                        SCOPE_1,
                                        SCOPE_2,
                                      "locations",
                                        "https://"RAR1"-1.resource.tld",
                                        "https://"RAR1"-2.resource.tld",
                                      "actions",
                                        "action1-"RAR1,
                                        "action2-"RAR1,
                                      "datatypes",
                                        "type1-"RAR1,
                                        "type2-"RAR1,
                                      "enriched",
                                        ENRICHED1,
                                        ENRICHED2,
                                      "privileges",
                                        PRIVILEGE1,
                                    RAR2,
                                      "scopes",
                                        SCOPE_1,
                                      "locations",
                                        "https://"RAR2"-1.resource.tld",
                                        "https://"RAR2"-2.resource.tld",
                                      "actions",
                                        "action1-"RAR2,
                                        "action2-"RAR2,
                                      "datatypes",
                                        "type1-"RAR2,
                                        "type2-"RAR2,
                                      "enriched",
                                        ENRICHED1,
                                      "privileges",
                                        PRIVILEGE1,
                                    RAR3,
                                      "scopes",
                                        "g_admin",
                                      "locations",
                                        "https://"RAR3".resource.tld",
                                      "actions",
                                        "action-"RAR3,
                                      "datatypes",
                                        "type1-"RAR3,
                                        "type2-"RAR3,
                                        "type3-"RAR3,
                                      "enriched",
                                        ENRICHED2,
                                      "privileges",
                                        PRIVILEGE1,
                                        PRIVILEGE2,
                                    RAR4);

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_rar_delete_plugin)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_rar_send_invalid_requests)
{
  // type invalid
  json_t * j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}s[s]}]",
                              "type", "error",
                              "locations",
                                "https://"RAR1"-1.resource.tld",
                              "actions",
                                "action1-"RAR1,
                              "datatypes",
                                "type1-"RAR1,
                              "access",
                                ENRICHED1,
                              "privileges",
                                PRIVILEGE1);
  char * str_rar, * rar_encoded, * url;
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST"&authorization_details=%s", rar_encoded);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "invalid_request"), 1);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);
  json_decref(j_rar);

  // locations invalid
  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}s[s]}]",
                              "type", RAR1,
                              "locations",
                                "https://"RAR1"-1.resource.tld-error",
                              "actions",
                                "action1-"RAR1,
                              "datatypes",
                                "type1-"RAR1,
                              "access",
                                ENRICHED1,
                              "privileges",
                                PRIVILEGE1);
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST"&authorization_details=%s", rar_encoded);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "invalid_request"), 1);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);
  json_decref(j_rar);

  // actions invalid
  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}s[s]}]",
                              "type", RAR1,
                              "locations",
                                "https://"RAR1"-1.resource.tld",
                              "actions",
                                "action1-error-"RAR1,
                              "datatypes",
                                "type1-"RAR1,
                              "access",
                                ENRICHED1,
                              "privileges",
                                PRIVILEGE1);
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST"&authorization_details=%s", rar_encoded);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "invalid_request"), 1);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);
  json_decref(j_rar);

  // datatypes invalid
  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}s[s]}]",
                              "type", RAR1,
                              "locations",
                                "https://"RAR1"-1.resource.tld",
                              "actions",
                                "action1-"RAR1,
                              "datatypes",
                                "type1-error-"RAR1,
                              "access",
                                ENRICHED1,
                              "privileges",
                                PRIVILEGE1);
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST"&authorization_details=%s", rar_encoded);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "invalid_request"), 1);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);
  json_decref(j_rar);

  // access invalid
  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}s[s]}]",
                              "type", RAR1,
                              "locations",
                                "https://"RAR1"-1.resource.tld",
                              "actions",
                                "action1-"RAR1,
                              "datatypes",
                                "type1-"RAR1,
                              "access",
                                "error",
                              "privileges",
                                PRIVILEGE1);
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST"&authorization_details=%s", rar_encoded);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "invalid_request"), 1);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);
  json_decref(j_rar);

  // privileges invalid
  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}s[s]}]",
                              "type", RAR1,
                              "locations",
                                "https://"RAR1"-1.resource.tld",
                              "actions",
                                "action1-"RAR1,
                              "datatypes",
                                "type1-"RAR1,
                              "access",
                                ENRICHED1,
                              "privileges",
                                "error");
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST"&authorization_details=%s", rar_encoded);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "invalid_request"), 1);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);
  json_decref(j_rar);

  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}s[s]}]",
                              "type", RAR3,
                              "locations",
                                "https://"RAR3".resource.tld",
                              "actions",
                                "action-"RAR3,
                              "datatypes",
                                "type1-"RAR3,
                              "access",
                                ENRICHED2,
                              "privileges",
                                PRIVILEGE1);
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST"&authorization_details=%s", rar_encoded);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "invalid_request"), 1);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);
  json_decref(j_rar);

  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}s[s]}]",
                              "type", RAR1,
                              "locations",
                                "https://"RAR1"-1.resource.tld",
                              "actions",
                                "action1-"RAR1,
                              "datatypes",
                                "type1-"RAR1,
                              "access",
                                ENRICHED1,
                              "privileges",
                                PRIVILEGE1);
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_3"&authorization_details=%s", rar_encoded);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "invalid_request"), 1);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);
  json_decref(j_rar);

  j_rar = json_pack("[{ss}]", "type", RAR4);
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST"&authorization_details=%s", rar_encoded);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "invalid_request"), 1);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);
  json_decref(j_rar);

}
END_TEST

START_TEST(test_oidc_rar_consent_error)
{
  struct _u_response resp;

  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/"RAR3,
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 404);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/"RAR3"/1",
                                U_OPT_HTTP_VERB, "PUT",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 404);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/error",
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 404);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/error/1",
                                U_OPT_HTTP_VERB, "PUT",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 404);
  ulfius_clean_response(&resp);

  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/error",
                                U_OPT_HTTP_VERB, "DELETE",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 404);
  ulfius_clean_response(&resp);

}
END_TEST

START_TEST(test_oidc_rar_set_consent_ok)
{
  json_t * j_body, * j_verif;
  struct _u_response resp;

  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/"RAR1,
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  j_verif = json_pack("{so}", "consent", json_false());
  ck_assert_ptr_ne(NULL, json_search(j_body, j_verif));
  json_decref(j_verif);
  json_decref(j_body);
  ulfius_clean_response(&resp);

  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/"RAR1"/1",
                                U_OPT_HTTP_VERB, "PUT",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, NULL), U_OK);

  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/"RAR1,
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  j_verif = json_pack("{so}", "consent", json_true());
  ck_assert_ptr_ne(NULL, json_search(j_body, j_verif));
  json_decref(j_verif);
  json_decref(j_body);
  ulfius_clean_response(&resp);

  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/"RAR1,
                                U_OPT_HTTP_VERB, "DELETE",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, NULL), U_OK);

}
END_TEST

START_TEST(test_oidc_rar_need_consent)
{
  json_t * j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}}]",
                              "type", RAR1,
                              "locations",
                                "https://"RAR1"-1.resource.tld",
                              "actions",
                                "action1-"RAR1,
                              "datatypes",
                                "type1-"RAR1,
                              "access",
                                ENRICHED1);
  char * str_rar, * rar_encoded, * url;
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST"&authorization_details=%s", rar_encoded);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 302, NULL, NULL, "consent"), 1);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);
  json_decref(j_rar);
}
END_TEST

START_TEST(test_oidc_rar_set_consent)
{
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/"RAR1"/1",
                                U_OPT_HTTP_VERB, "PUT",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, NULL), U_OK);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/"RAR2"/1",
                                U_OPT_HTTP_VERB, "PUT",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, NULL), U_OK);
}
END_TEST

START_TEST(test_oidc_rar_delete_consent)
{
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/"RAR1,
                                U_OPT_HTTP_VERB, "DELETE",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, NULL), U_OK);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT"/"RAR2,
                                U_OPT_HTTP_VERB, "DELETE",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, NULL), U_OK);
}
END_TEST

START_TEST(test_oidc_rar_set_consent_client_pubkey)
{
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT_PUBKEY_ID"/"RAR1"/1",
                                U_OPT_HTTP_VERB, "PUT",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, NULL), U_OK);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT_PUBKEY_ID"/"RAR2"/1",
                                U_OPT_HTTP_VERB, "PUT",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, NULL), U_OK);
}
END_TEST

START_TEST(test_oidc_rar_delete_consent_client_pubkey)
{
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT_PUBKEY_ID"/"RAR1,
                                U_OPT_HTTP_VERB, "DELETE",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, NULL), U_OK);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/rar/"CLIENT_PUBKEY_ID"/"RAR2,
                                U_OPT_HTTP_VERB, "DELETE",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, NULL), U_OK);
}
END_TEST

START_TEST(test_oidc_rar_at_code_refresh_introspect_ok)
{
  struct _u_request req;
  struct _u_response resp;
  char * str_rar, * rar_encoded, * url, * code, * access_token;
  json_t * j_rar, * j_jwt_content, * j_body;
  jwt_t * jwt;

  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}}]",
                    "type", RAR1,
                    "locations",
                      "https://"RAR1"-1.resource.tld",
                    "actions",
                      "action1-"RAR1,
                    "datatypes",
                      "type1-"RAR1,
                    "access",
                      ENRICHED1);
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST"&authorization_details=%s", rar_encoded);

  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, url,
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);

  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  code = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "code=")+strlen("code="));
  if (strchr(code, '&') != NULL) {
    *strchr(code, '&') = '\0';
  }
  access_token = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "access_token=")+strlen("access_token="));
  if (strchr(access_token, '&') != NULL) {
    *strchr(access_token, '&') = '\0';
  }
  r_jwt_init(&jwt);
  r_jwt_parse(jwt, access_token, 0);
  json_object_del(json_array_get(j_rar, 0), "access");
  j_jwt_content = r_jwt_get_full_claims_json_t(jwt);
  ck_assert_ptr_ne(NULL, json_object_get(j_jwt_content, "authorization_details"));
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_jwt_content, "authorization_details"), json_array_get(j_rar, 0)));
  ck_assert_int_gt(json_string_length(json_object_get(json_object_get(json_array_get(json_object_get(j_jwt_content, "authorization_details"), 0), "access"), ENRICHED1)), 0);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/token",
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_AUTH_BASIC_USER, CLIENT,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_PASSWORD,
                                U_OPT_POST_BODY_PARAMETER, "grant_type", "authorization_code",
                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                U_OPT_POST_BODY_PARAMETER, "redirect_uri", "../../test-oidc.html?param=client3",
                                U_OPT_POST_BODY_PARAMETER, "code", code,
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_jwt_content, "authorization_details"), json_array_get(j_rar, 0)));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_jwt_content);
  
  r_jwt_init(&jwt);
  r_jwt_parse(jwt, json_string_value(json_object_get(j_body, "access_token")), 0);
  j_jwt_content = r_jwt_get_full_claims_json_t(jwt);
  ck_assert_ptr_ne(NULL, json_object_get(j_jwt_content, "authorization_details"));
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_jwt_content, "authorization_details"), json_array_get(j_rar, 0)));
  ck_assert_int_gt(json_string_length(json_object_get(json_object_get(json_array_get(json_object_get(j_jwt_content, "authorization_details"), 0), "access"), ENRICHED1)), 0);
  r_jwt_free(jwt);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/token",
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_AUTH_BASIC_USER, CLIENT,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_PASSWORD,
                                U_OPT_POST_BODY_PARAMETER, "grant_type", "refresh_token",
                                U_OPT_POST_BODY_PARAMETER, "refresh_token", json_string_value(json_object_get(j_body, "refresh_token")),
                                U_OPT_NONE);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_jwt_content, "authorization_details"), json_array_get(j_rar, 0)));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  json_decref(j_jwt_content);
  
  r_jwt_init(&jwt);
  r_jwt_parse(jwt, json_string_value(json_object_get(j_body, "access_token")), 0);
  j_jwt_content = r_jwt_get_full_claims_json_t(jwt);
  ck_assert_ptr_ne(NULL, json_object_get(j_jwt_content, "authorization_details"));
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_jwt_content, "authorization_details"), json_array_get(j_rar, 0)));
  ck_assert_int_gt(json_string_length(json_object_get(json_object_get(json_array_get(json_object_get(j_jwt_content, "authorization_details"), 0), "access"), ENRICHED1)), 0);
  r_jwt_free(jwt);
  json_decref(j_jwt_content);
  json_decref(j_body);
  
  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&req,
                                U_OPT_HTTP_URL, SERVER_URI"/"PLUGIN_NAME"/introspect",
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_AUTH_BASIC_USER, CLIENT,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_PASSWORD,
                                U_OPT_POST_BODY_PARAMETER, "token", access_token,
                                U_OPT_POST_BODY_PARAMETER, "token_type_hint", "access_token",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(NULL, j_body = ulfius_get_json_body_response(&resp, NULL));
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_body, "authorization_details"), json_array_get(j_rar, 0)));
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  o_free(code);
  o_free(access_token);
  json_decref(j_rar);
  json_decref(j_body);
}
END_TEST

START_TEST(test_oidc_rar_at_reduced_ok)
{
  struct _u_response resp;
  char * str_rar, * rar_encoded, * url, * access_token;
  json_t * j_rar, * j_jwt_content;
  jwt_t * jwt;

  j_rar = json_pack("[{sss[s]}{sss[s]}]",
                    "type", RAR1,
                    "actions",
                      "action1-"RAR1,
                    "type", RAR3,
                    "actions",
                      "action-"RAR3);
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT"&redirect_uri=..%%2f..%%2ftest-oidc.html?param=client3&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST" "SCOPE_3"&authorization_details=%s", rar_encoded);

  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, url,
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);

  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  access_token = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "access_token=")+strlen("access_token="));
  if (strchr(access_token, '&') != NULL) {
    *strchr(access_token, '&') = '\0';
  }
  r_jwt_init(&jwt);
  r_jwt_parse(jwt, access_token, 0);
  j_jwt_content = r_jwt_get_full_claims_json_t(jwt);
  ck_assert_ptr_ne(NULL, json_object_get(j_jwt_content, "authorization_details"));
  ck_assert_int_eq(1, json_array_size(json_object_get(j_jwt_content, "authorization_details")));
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_jwt_content, "authorization_details"), json_array_get(j_rar, 0)));
  ck_assert_ptr_eq(json_object_get(json_object_get(json_array_get(json_object_get(j_jwt_content, "authorization_details"), 0), "access"), ENRICHED1), NULL);
  ck_assert_ptr_eq(json_object_get(json_array_get(json_object_get(j_jwt_content, "authorization_details"), 0), "access"), NULL);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
  json_decref(j_jwt_content);
  json_decref(j_rar);
  o_free(access_token);
}
END_TEST

START_TEST(test_oidc_rar_device_verification_valid)
{
  struct _u_request req;
  struct _u_response resp;
  json_t * j_resp, * j_grant, * j_rar, * j_jwt_content;
  const char * redirect_uri, * code, * device_code;
  jwt_t * jwt;
  char * str_rar;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  j_rar = json_pack("[{sss[s]s[s]s[s]}]",
                    "type", RAR1,
                    "locations",
                      "https://"RAR1"-1.resource.tld",
                    "actions",
                      "action1-"RAR1,
                    "datatypes",
                      "type1-"RAR1);
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  ulfius_set_request_properties(&req,
                                U_OPT_HTTP_VERB, "POST",
                                U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/device_authorization/",
                                U_OPT_POST_BODY_PARAMETER, "grant_type", "device_authorization",
                                U_OPT_POST_BODY_PARAMETER, "client_id", CLIENT,
                                U_OPT_POST_BODY_PARAMETER, "scope", SCOPE_LIST,
                                U_OPT_POST_BODY_PARAMETER, "authorization_details", str_rar,
                                U_OPT_AUTH_BASIC_USER, CLIENT,
                                U_OPT_AUTH_BASIC_PASSWORD, CLIENT_PASSWORD,
                                U_OPT_NONE);
  o_free(str_rar);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "device_code"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "user_code"), NULL);
  ck_assert_ptr_ne(code = json_string_value(json_object_get(j_resp, "user_code")), NULL);
  ck_assert_ptr_ne(device_code = json_string_value(json_object_get(j_resp, "device_code")), NULL);
  ck_assert_str_eq(json_string_value(json_object_get(j_resp, "verification_uri")), "http://localhost:4593/api/" PLUGIN_NAME "/device");
  ck_assert_ptr_ne(json_object_get(j_resp, "verification_uri_complete"), NULL);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "expires_in")), 600);
  ck_assert_int_eq(json_integer_value(json_object_get(j_resp, "interval")), 5);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  j_grant = json_pack("{ss}", "scope", SCOPE_LIST);
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  o_free(user_req.http_url);
  user_req.http_url = msprintf(SERVER_URI "/" PLUGIN_NAME "/device?code=%s&g_continue", code);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  ck_assert_ptr_ne(redirect_uri = u_map_get(resp.map_header, "Location"), NULL);
  ck_assert_ptr_ne(o_strstr(redirect_uri, "prompt=deviceComplete"), NULL);
  ulfius_clean_response(&resp);
  
  j_grant = json_pack("{ss}", "scope", "");
  run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT, NULL, NULL, j_grant, NULL, 200, NULL, NULL, NULL);
  json_decref(j_grant);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code");
  u_map_put(req.map_post_body, "client_id", CLIENT);
  u_map_put(req.map_post_body, "device_code", device_code);
  req.auth_basic_user = o_strdup(CLIENT);
  req.auth_basic_password = o_strdup(CLIENT_PASSWORD);
  json_decref(j_resp);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(200, resp.status);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "authorization_details"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "refresh_token"), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "id_token"), NULL);
  ck_assert_int_eq(1, json_array_size(json_object_get(j_resp, "authorization_details")));
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_resp, "authorization_details"), json_array_get(j_rar, 0)));
  ck_assert_ptr_eq(json_object_get(json_object_get(json_array_get(json_object_get(j_resp, "authorization_details"), 0), "access"), ENRICHED1), NULL);
  ck_assert_ptr_eq(json_object_get(json_array_get(json_object_get(j_resp, "authorization_details"), 0), "access"), NULL);
  
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(SCOPE_LIST, r_jwt_get_claim_str_value(jwt, "aud"));
  j_jwt_content = r_jwt_get_full_claims_json_t(jwt);
  ck_assert_ptr_ne(NULL, json_object_get(j_jwt_content, "authorization_details"));
  ck_assert_int_eq(1, json_array_size(json_object_get(j_jwt_content, "authorization_details")));
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_jwt_content, "authorization_details"), json_array_get(j_rar, 0)));
  ck_assert_ptr_eq(json_object_get(json_object_get(json_array_get(json_object_get(j_jwt_content, "authorization_details"), 0), "access"), ENRICHED1), NULL);
  ck_assert_ptr_eq(json_object_get(json_array_get(json_object_get(j_jwt_content, "authorization_details"), 0), "access"), NULL);
  r_jwt_free(jwt);
  
  json_decref(j_resp);
  json_decref(j_rar);
  json_decref(j_jwt_content);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
}
END_TEST

START_TEST(test_oidc_rar_add_client_pubkey)
{
  json_t * j_client = json_pack("{ss ss so s[s] s[ssss] s[s] ss so s[sss]}", "client_id", CLIENT_PUBKEY_ID, "name", CLIENT_PUBKEY_NAME, "confidential", json_true(), "redirect_uri", CLIENT_PUBKEY_REDIRECT, "authorization_type", "code", "token", "id_token", "client_credentials", "scope", CLIENT_SCOPE, CLIENT_PUBKEY_PARAM, pubkey_1_pem, "enabled", json_true(), "authorization_data_types", RAR1, RAR2, RAR3);
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_rar_delete_client_pubkey)
{
  json_t * j_param = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_PUBKEY_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_PUBKEY_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_rar_at_unsigned_no_rar)
{
  struct _u_response resp;
  json_t * j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}}]",
                              "type", RAR1,
                              "locations",
                                "https://"RAR1"-1.resource.tld",
                              "actions",
                                "action1-"RAR1,
                              "datatypes",
                                "type1-"RAR1,
                              "access",
                                ENRICHED1), * j_jwt_content;
  char * str_rar, * rar_encoded, * url, * access_token;
  jwt_t * jwt;
  
  str_rar = json_dumps(j_rar, JSON_COMPACT);
  rar_encoded = ulfius_url_encode(str_rar);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?response_type="RESPONSE_TYPE"&g_continue&client_id="CLIENT_PUBKEY_ID"&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope="SCOPE_LIST"&authorization_details=%s", CLIENT_PUBKEY_REDIRECT_ESCAPED, rar_encoded);
  
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, url,
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  o_free(url);
  o_free(str_rar);
  o_free(rar_encoded);

  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  access_token = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "access_token=")+strlen("access_token="));
  if (strchr(access_token, '&') != NULL) {
    *strchr(access_token, '&') = '\0';
  }
  r_jwt_init(&jwt);
  r_jwt_parse(jwt, access_token, 0);
  j_jwt_content = r_jwt_get_full_claims_json_t(jwt);
  ck_assert_ptr_eq(NULL, json_object_get(j_jwt_content, "authorization_details"));
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
  json_decref(j_jwt_content);
  json_decref(j_rar);
  o_free(access_token);
}
END_TEST

START_TEST(test_oidc_rar_at_signed_ok)
{
  struct _u_response resp;
  jwt_t * jwt_request = NULL, * jwt;
  json_t * j_rar, * j_jwt_content;
  char * url, * request, * access_token;
  r_jwt_init(&jwt_request);
  
  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}}]",
                    "type", RAR1,
                    "locations",
                      "https://"RAR1"-1.resource.tld",
                    "actions",
                      "action1-"RAR1,
                    "datatypes",
                      "type1-"RAR1,
                    "access",
                      ENRICHED1);
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_request, privkey_1_jwk, NULL), RHN_OK);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_str_value(jwt_request, "state", "xyzabcd");
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt_request, "authorization_details", j_rar), RHN_OK);
  ck_assert_ptr_ne(NULL, request = r_jwt_serialize_signed(jwt_request, NULL, 0));
  ck_assert_ptr_ne(request, NULL);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?g_continue&request=%s", request);
  
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, url,
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  o_free(url);

  access_token = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "access_token=")+strlen("access_token="));
  if (strchr(access_token, '&') != NULL) {
    *strchr(access_token, '&') = '\0';
  }
  r_jwt_init(&jwt);
  r_jwt_parse(jwt, access_token, 0);
  j_jwt_content = r_jwt_get_full_claims_json_t(jwt);
  json_object_del(json_array_get(j_rar, 0), "access");
  ck_assert_ptr_ne(NULL, json_object_get(j_jwt_content, "authorization_details"));
  ck_assert_int_eq(1, json_array_size(json_object_get(j_jwt_content, "authorization_details")));
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_jwt_content, "authorization_details"), json_array_get(j_rar, 0)));
  ck_assert_ptr_ne(json_object_get(json_object_get(json_array_get(json_object_get(j_jwt_content, "authorization_details"), 0), "access"), ENRICHED1), NULL);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
  json_decref(j_jwt_content);
  json_decref(j_rar);
  o_free(request);
  o_free(access_token);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_rar_at_encrypted_ok)
{
  struct _u_response resp;
  jwt_t * jwt_request = NULL, * jwt;
  json_t * j_rar, * j_jwt_content;
  char * url, * request, * access_token;
  r_jwt_init(&jwt_request);
  
  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}}]",
                    "type", RAR1,
                    "locations",
                      "https://"RAR1"-1.resource.tld",
                    "actions",
                      "action1-"RAR1,
                    "datatypes",
                      "type1-"RAR1,
                    "access",
                      ENRICHED1);
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256), RHN_OK);
  r_jwt_set_enc_alg(jwt_request, R_JWA_ALG_RSA1_5);
  r_jwt_set_enc(jwt_request, R_JWA_ENC_A128CBC);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_request, privkey_1_jwk, NULL), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys_pem_der(jwt_request, R_FORMAT_PEM, NULL, 0, (unsigned char *)pubkey_2_pem, o_strlen(pubkey_2_pem)), RHN_OK);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_str_value(jwt_request, "state", "xyzabcd");
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt_request, "authorization_details", j_rar), RHN_OK);
  ck_assert_ptr_ne(NULL, request = r_jwt_serialize_nested(jwt_request, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0));
  ck_assert_ptr_ne(request, NULL);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?g_continue&request=%s", request);
  
  ulfius_init_response(&resp);
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, url,
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_NONE);
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(302, resp.status);
  o_free(url);

  access_token = o_strdup(strstr(u_map_get(resp.map_header, "Location"), "access_token=")+strlen("access_token="));
  if (strchr(access_token, '&') != NULL) {
    *strchr(access_token, '&') = '\0';
  }
  r_jwt_init(&jwt);
  r_jwt_parse(jwt, access_token, 0);
  j_jwt_content = r_jwt_get_full_claims_json_t(jwt);
  json_object_del(json_array_get(j_rar, 0), "access");
  ck_assert_ptr_ne(NULL, json_object_get(j_jwt_content, "authorization_details"));
  ck_assert_int_eq(1, json_array_size(json_object_get(j_jwt_content, "authorization_details")));
  ck_assert_ptr_ne(NULL, json_search(json_object_get(j_jwt_content, "authorization_details"), json_array_get(j_rar, 0)));
  ck_assert_ptr_ne(json_object_get(json_object_get(json_array_get(json_object_get(j_jwt_content, "authorization_details"), 0), "access"), ENRICHED1), NULL);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
  json_decref(j_jwt_content);
  json_decref(j_rar);
  o_free(request);
  o_free(access_token);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_rar_at_signed_error)
{
  jwt_t * jwt_request = NULL;
  json_t * j_rar;
  char * url, * request;
  
  r_jwt_init(&jwt_request);
  
  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}}]",
                    "type", RAR1,
                    "locations",
                      "https://"RAR1"-1.resource.tld",
                    "actions",
                      "action1-"RAR1,
                    "datatypes",
                      "type1-"RAR1,
                    "access",
                      ENRICHED1);
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_json_str(jwt_request, privkey_1_jwk, NULL), RHN_OK);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_str_value(jwt_request, "state", "xyzabcd");
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt_request, "authorization_details", j_rar), RHN_OK);
  ck_assert_ptr_ne(NULL, request = r_jwt_serialize_signed(jwt_request, NULL, 0));
  ck_assert_ptr_ne(request, NULL);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?g_continue&request=%s", request);
  
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, url,
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_NONE);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
  json_decref(j_rar);
}
END_TEST

START_TEST(test_oidc_rar_at_unsigned_error)
{
  jwt_t * jwt_request = NULL;
  json_t * j_rar;
  char * url, * request;
  
  r_jwt_init(&jwt_request);
  
  j_rar = json_pack("[{sss[s]s[s]s[s]s{s[]}}]",
                    "type", RAR1,
                    "locations",
                      "https://"RAR1"-1.resource.tld",
                    "actions",
                      "action1-"RAR1,
                    "datatypes",
                      "type1-"RAR1,
                    "access",
                      ENRICHED1);
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_NONE), RHN_OK);
  r_jwt_set_claim_str_value(jwt_request, "aud", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "response_type", RESPONSE_TYPE);
  r_jwt_set_claim_str_value(jwt_request, "client_id", CLIENT_PUBKEY_ID);
  r_jwt_set_claim_str_value(jwt_request, "redirect_uri", CLIENT_PUBKEY_REDIRECT);
  r_jwt_set_claim_str_value(jwt_request, "scope", SCOPE_LIST);
  r_jwt_set_claim_str_value(jwt_request, "state", "xyzabcd");
  r_jwt_set_claim_str_value(jwt_request, "nonce", "nonce1234");
  ck_assert_int_eq(r_jwt_set_claim_json_t_value(jwt_request, "authorization_details", j_rar), RHN_OK);
  ck_assert_ptr_ne(NULL, request = r_jwt_serialize_signed_unsecure(jwt_request, NULL, 0));
  ck_assert_ptr_ne(request, NULL);
  url = msprintf(SERVER_URI"/"PLUGIN_NAME"/auth?g_continue&request=%s", request);
  
  ulfius_set_request_properties(&user_req,
                                U_OPT_HTTP_URL, url,
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_NONE);
  ck_assert_int_eq(run_simple_test(&user_req, "GET", url, NULL, NULL, NULL, NULL, 403, NULL, NULL, NULL), 1);
  o_free(url);
  o_free(request);
  r_jwt_free(jwt_request);
  json_decref(j_rar);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc rich authentication request");
  tc_core = tcase_create("test_oidc_rich_authentication_request");
  tcase_add_test(tc_core, test_oidc_rar_add_plugin_unsigned);
  tcase_add_test(tc_core, test_oidc_rar_send_invalid_requests);
  tcase_add_test(tc_core, test_oidc_rar_consent_error);
  tcase_add_test(tc_core, test_oidc_rar_set_consent_ok);
  tcase_add_test(tc_core, test_oidc_rar_need_consent);
  tcase_add_test(tc_core, test_oidc_rar_set_consent);
  tcase_add_test(tc_core, test_oidc_rar_at_code_refresh_introspect_ok);
  tcase_add_test(tc_core, test_oidc_rar_at_reduced_ok);
  tcase_add_test(tc_core, test_oidc_rar_device_verification_valid);
  tcase_add_test(tc_core, test_oidc_rar_delete_consent);
  tcase_add_test(tc_core, test_oidc_rar_delete_plugin);
  tcase_add_test(tc_core, test_oidc_rar_add_plugin_signed_unencrypted);
  tcase_add_test(tc_core, test_oidc_rar_add_client_pubkey);
  tcase_add_test(tc_core, test_oidc_rar_set_consent_client_pubkey);
  tcase_add_test(tc_core, test_oidc_rar_at_unsigned_no_rar);
  tcase_add_test(tc_core, test_oidc_rar_at_unsigned_error);
  tcase_add_test(tc_core, test_oidc_rar_at_signed_ok);
  tcase_add_test(tc_core, test_oidc_rar_at_encrypted_ok);
  tcase_add_test(tc_core, test_oidc_rar_delete_consent_client_pubkey);
  tcase_add_test(tc_core, test_oidc_rar_delete_client_pubkey);
  tcase_add_test(tc_core, test_oidc_rar_delete_plugin);
  tcase_add_test(tc_core, test_oidc_rar_add_plugin_signed_encrypted);
  tcase_add_test(tc_core, test_oidc_rar_add_client_pubkey);
  tcase_add_test(tc_core, test_oidc_rar_set_consent_client_pubkey);
  tcase_add_test(tc_core, test_oidc_rar_at_unsigned_no_rar);
  tcase_add_test(tc_core, test_oidc_rar_at_unsigned_error);
  tcase_add_test(tc_core, test_oidc_rar_at_signed_error);
  tcase_add_test(tc_core, test_oidc_rar_at_encrypted_ok);
  tcase_add_test(tc_core, test_oidc_rar_delete_consent_client_pubkey);
  tcase_add_test(tc_core, test_oidc_rar_delete_client_pubkey);
  tcase_add_test(tc_core, test_oidc_rar_delete_plugin);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, scope_req, client_req;
  struct _u_response auth_resp, scope_resp, client_resp;
  int res, do_test = 0;
  json_t * j_body, * j_client;
  char * cookie;

  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");

  ulfius_init_request(&admin_req);
  ulfius_init_request(&user_req);

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&scope_req);
  ulfius_init_request(&client_req);
  ulfius_init_response(&auth_resp);
  ulfius_init_response(&scope_resp);
  ulfius_init_response(&client_resp);
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
      u_map_put(client_req.map_header, "Cookie", cookie);
      o_free(cookie);
      do_test = 1;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication admin");
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  ulfius_set_request_properties(&client_req,
                                U_OPT_HTTP_VERB, "GET",
                                U_OPT_HTTP_URL, SERVER_URI "/client/" CLIENT,
                                U_OPT_NONE);
  ulfius_send_http_request(&client_req, &client_resp);
  j_client = ulfius_get_json_body_response(&client_resp, NULL);
  ulfius_clean_response(&client_resp);
  json_object_set_new(j_client, "authorization_data_types", json_pack("[sss]", RAR1, RAR2, RAR3));
  json_array_append_new(json_object_get(j_client, "authorization_type"), json_string("device_authorization"));
  ulfius_set_request_properties(&client_req,
                                U_OPT_HTTP_URL, SERVER_URI "/client/" CLIENT,
                                U_OPT_HTTP_VERB, "PUT",
                                U_OPT_JSON_BODY, j_client,
                                U_OPT_NONE);
  ulfius_send_http_request(&client_req, NULL);

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
        u_map_put(scope_req.map_header, "Cookie", cookie);
        u_map_put(user_req.map_header, "Cookie", cookie);
        o_free(cookie);

        scope_req.http_verb = strdup("PUT");
        scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
        j_body = json_pack("{ss}", "scope", SCOPE_LIST);
        ulfius_set_json_body_request(&scope_req, j_body);
        json_decref(j_body);
        if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK || scope_resp.status != 200) {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
          do_test = 0;
        } else {
          y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope OK");
        }
        ulfius_clean_response(&scope_resp);
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

  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&scope_req, j_body);
  json_decref(j_body);
  if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
  }

  char * url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);

  json_object_set_new(j_client, "authorization_data_types", json_pack("[]"));
  json_array_remove(json_object_get(j_client, "authorization_type"), json_array_size(json_object_get(j_client, "authorization_type"))-1);
  ulfius_set_request_properties(&client_req,
                                U_OPT_HTTP_URL, SERVER_URI "/client/" CLIENT,
                                U_OPT_HTTP_VERB, "PUT",
                                U_OPT_JSON_BODY, j_client,
                                U_OPT_NONE);
  ulfius_send_http_request(&client_req, NULL);

  json_decref(j_client);
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&scope_req);
  ulfius_clean_request(&client_req);
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
