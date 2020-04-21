/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/abstract.h>
#include <check.h>

#include <orcania.h>
#include <yder.h>
#include <ulfius.h>
#include <rhonabwy.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define USERNAME "user1"
#define PASSWORD "password"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"
#define SCOPE_LIST "openid"
#define SCOPE_LIST_WITH_AUTH "scope1 openid"
#define CLIENT "client4_id"
#define CLIENT_PUBLIC "client1_id"
#define CLIENT_ERROR "error"
#define CLIENT_SECRET "secret"
#define REDIRECT_URI "../../test-oidc.html?param=client4"
#define REDIRECT_URI_PUBLIC "../../test-oidc.html?param=client1_cb1"
#define NONCE_TEST "nonce5678"
#define STATE_TEST "abcxyz"

#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "oidc_jwks"
#define PLUGIN_DISPLAY_NAME "oidc with jwks"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600

#define CLIENT_AUTH_TOKEN_MAX_AGE 3600
#define CLIENT_PUBKEY_PARAM "pubkey"
#define CLIENT_JWKS_PARAM "jwks"
#define CLIENT_JWKS_URI_PARAM "jwks_uri"
#define CLIENT_ID "client_kid"
#define CLIENT_NAME "client with kid"
#define CLIENT_REDIRECT "https://glewlwyd.local/"
#define CLIENT_SCOPE "scope1"
#define CLIENT_ENC "A128CBC-HS256"
#define CLIENT_PUBKEY_ALG "RSA1_5"
#define CLIENT_SECRET_ALG "A128GCMKW"
#define KID_1 "key-1"
#define KID_2 "key-2"
#define KID_3 "key-3"
#define KID_4 "key-4"

const char jwks_privkey[] = 
"{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AOidO2hPJFDK-jHdQ6p-SDGNAS3SbTCq1DN7Yv4kmClva"
"5FtgLFIG8VG0hvn8RKN2kpqmNOa30KsOlYW9GqUCy6esFn0yqyNC_01IVY67qPIU5SRbCD88UXSfqsnhN"
"sFgwU76OmpamqBGXUenZRrewNleNfYLJ6fNQO5n1rOa_UCcOaFqNLjjAcS9Z6e6h4Edlhz6ecYEVW6ZYF"
"ODRNmyq_Pf0nZGgUjKXuAzEb8GdhiO99TcsLoc7RxTbfsvqLGofPXhY5EfWksNyeqJtINUEtMC78nADM6"
"J_jFyeqBE3Tsqk1M6aQFo-8xy8kQ_bT7pdL9xh9w1UZ_kFg5pBMsaPk\",\"e\":\"AQAB\",\"d\":\""
"ANWOxOPXBPhH4bu18FGu7ojPc62l6ykrLPa26QN6hVhFOvShG-2mzhgoFO4Z23G1WhvIEdbz8NU9WbGAE"
"ZVnpXx_pFhyLUCNndwx0xFfuYgUeueDO0pt7vSzdCeeeJK8VLWRcxxStahiLgUgvnts0dskZfWEOjLG59"
"0rpemwadzdSGK44zgRhJQ1gr0PrsWoqZXWKT9OE5PwMQwL5cnN3GvXX2-PnxLUnjXzK9VN6nKl0dP67HK"
"rBcrHZ4HXbLAoc1BjStidW1MmESNWPBkcnq-yKjmkrXzMbTH0ufJY1zYu6obdgLYDDN_QJgR4w3sXS2tN"
"BRMj0XCmgFkAknD7mAE\",\"p\":\"AOoXE9yq9elQvRJ1bV0EjEfa1D1c0eubEHjStluxKA37QnpqAKL"
"vMv44DiGdbFAewvkE8gP6Yjv-ls8ynvcJuYjcDyUnN2jjPaYKOopaqoejq0LQJtXGHiPUX5929y-5uDAu"
"e0Mu5C2x3_uv0MXZS316-9oIK0ooszurC6tkvDTZ\",\"q\":\"AP5iyitBD-0YUnQ4VIakwWaOx6wtLt"
"GuQgTu3o1hneo9rIY5MwvSSfT2PmkjGqFRzhQTv504roz8J2kSSzurV32JGer9H7db45afiDBl_UiEbds"
"X_LKScOYGgWnm8yDm2YY_UzwbmD4H0xCDUYszbSSfYiVpBvZIe2sKpOK4YsEh\",\"qi\":\"AMULGD_n"
"LWXAfOa_-dtQRP7yXENDQtKMwsTQrVrQgCynH0EVGWEUyPXA8PsHtzUiR_bLNGpdDgiMnfiEvXuv-Y_y9"
"kzUCDi9RtA8tzTTq6EUR_YK0MJd4yiRYOnK0OAXTyTQPPlS-pUWk0J9l4p4uxTJe0m7J418naPLS9l7Xf"
"kd\",\"dp\":\"AId1u0SimZLd6ctYsGR3UUXzV4X6xG72WF3ScTw2E9ujXiDAXoXqrTN29JZ3JkpmwqS"
"fO_0ZUucst9BGlr6VnguYbBsvylyjwvTmTmHpfWzoRR5wnUhvUNmi94KrsPapHfCjtSh3ZgsbN2XJo6IZ"
"0BlYpYzR1VsgmjcZD7Oqo05h\",\"dq\":\"ALHiWwUMJhrhmybyDQlqRGN3DGF15vtxI3FXqACtdkPKh"
"M4HSY7GqjjFyLa0eXa9QaIAfUlvzX-BA_4RcNJ06mU6bglIn9kURH2baRyO9SK0mC1RBL_Kb3AqtGxdtz"
"4Wr52UwpuRoFAgIJO3gFoayAOIAJWwb9HgtY0QkGSKE2SB\",\"kid\":\"" KID_1 "\",\"alg\":\"RS256\"},{\"kty\":\"RS"
"A\",\"n\":\"AMZGRVyWHvHCkbGpGF6xdhKSjYwX1q5xtS-9_rATkpGyp5f-vCl9uUgdD0CZZIuuEvWsR"
"vp1zt-JZVS9GrnoWBLZXzafHKO4pADMPPGlzaBsEmp4E5S7t6c4LGMgXExDoBs8jbp3TwbUeiyIsHyQzl"
"Y5pfg8_2Stp-PtoOWBVpWvhp1uxVuvvIp5TfHK3q2q3Iziggvja-p_cLji95AAXOLBEfaRklMLPM0aMm9"
"96-dX7Yq-cUO5ptCBEoRBcPlEJjFP9ZY_Hb0_3W8BIpkvf_zTcGsgIrcx17mIp9yRQcQ9pQNSa5kpk3nf"
"v2BZ6tJHu8KfKsA3WesYOkMM_6VoFRk\",\"e\":\"AQAB\",\"d\":\"X3No5N-oWf6vIPYks0F_dAV1"
"eyHmyegXr7opqB5kCxwUromFj_vkfKDwvMqbqtrMadTb_qtEQjzkuVyoRyNhcwGOYr9KjE7RNUkddb-6N"
"CaS3wqbcpjEGw5h3_6uMFDF_RazrDbPppwXjOTpAa68hqoOCmljEda_4mx9br9LLZePk-g0L1YE62-ShM"
"_ThI-azzrCNodKc37j6jVZ8x3gYACM2vtJTc-o7EOO-00bjyDrOKlJGLB9lGTSbSOij-Ilzmd_S58ykku"
"I-t6VULFEjnPed46W_S7fsVkTBlHab6zGTFCMWSpj1_EVDXdH2IcGJ1UgrHTQyiYmmKUkIqv6mQ\",\"p"
"\":\"ANqoPnFPan_AhngjrRrxtbT5aTyGcqreyrkE9g4zgAFdaSYXkUbIRQXcmp9KvoYk3rXr2SYolWWe"
"IhpMIDKbUL6ZR6GXxQw_YcNVVY_haPCI0OyG-qMnVykYIcvgyAUeupZGT3gZaAdXR2BTxNqPepV-MIAIv"
"8DU7upttwHu06-H\",\"q\":\"AOgi46IPh9oogaCnlnN7iex3VmbTy1T97vtM9qGIDy-kCipBkfUJbXk"
"JnZ6LhSnoeeE5oKZn-CTriBXR4Bsjs7YiSUrEcNU5ZmBIs_56o6SyuniA71L3-bxfvHnwB5ysNFGKgKId"
"7Skfx7u9f-AEGs_qA7kQ1w714DbFQYE2Pv5f\",\"qi\":\"eU35yvBcZiZ2Jzs8UU9CT1uJ9z5OjT-hg"
"1QlkbQgPHQB1JhFsoMYqBsYpaUttwrCHbTJjW13-7fvEoFXS6RJm4qGg-LfY65LeCcF6djXr6XumqlJNM"
"lFWF8aK5AZIiSZ_HUn5mdNRwbiONgmFwYjv3_nqBIfrXJ3C55FR9CcvD4\",\"dp\":\"AMFROlPH2Oq1"
"9q1FLYjC5tnoIMioPb0gWK8X2ctYcPXD9nD9KS4hZhT2o6Xt2WCUPGsu57-65cr_8jq5z0Wu18aLki8mF"
"crsRq0CRzF8IuF2tPBJrlKNN5xXf5nXVEBimKi_5QbTv4ut-KcLqOFrNP_yn0KzeYUtPUX6VnDZDEMF\""
",\"dq\":\"AJnn_9pDx8N5VbBpTFPWlXRFDvDv_QClt5u_xEkGh2MDtIWdoaK_lGhKWslyIWDOtHgCGCQ"
"cDKaVzk0BMD9uJUldZBCBO3nzK5Asw8G2F-crZHxep83vgRFGvBRwcuuKNMnXNT_G7aV1X5x2oGCq-Aff"
"VIaPxrYxiG1nzO1ZRNyr\",\"kid\":\"" KID_2 "\",\"alg\":\"PS512\"},{\"kty\":\"EC\",\"x\":\"AJ6TXabOS7Blc_B"
"NQVqQgp1nEwmatr8g9_HlPaoP4MPe\",\"y\":\"ALbKJWr4c4tksiv2IMWbfq09gghvuaR1pO2S_QjjX"
"UtZ\",\"d\":\"Xk9lCflRiR6ErF1nqwSYhAFsOteufFotEi2z2xWDHks\",\"crv\":\"P-256\",\"k"
"id\":\"" KID_3 "\",\"alg\":\"ES384\"},{\"kty\":\"oct\",\"k\":\"Kt5w3prEDTYJn8IveV1JtjXvtlAX0WRSEcEHxmND"
"bP3aY760nHjA4VlCvxJQCYTSE1C1KObMmEnwjHrJzBedP-rqjn0SlzovvYyYWJL7Ujukqg4lhQxkLO5FZ"
"jBNy1_i1-J3jPbP-DccD31-Kbxxmudqzd9LFVobDGoNvf-DdkQ\",\"kid\":\"" KID_4 "\",\"alg\":\"HS256\"}]}";
const char jwks_privkey_alg_missing[] = 
"{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AOidO2hPJFDK-jHdQ6p-SDGNAS3SbTCq1DN7Yv4kmClva"
"5FtgLFIG8VG0hvn8RKN2kpqmNOa30KsOlYW9GqUCy6esFn0yqyNC_01IVY67qPIU5SRbCD88UXSfqsnhN"
"sFgwU76OmpamqBGXUenZRrewNleNfYLJ6fNQO5n1rOa_UCcOaFqNLjjAcS9Z6e6h4Edlhz6ecYEVW6ZYF"
"ODRNmyq_Pf0nZGgUjKXuAzEb8GdhiO99TcsLoc7RxTbfsvqLGofPXhY5EfWksNyeqJtINUEtMC78nADM6"
"J_jFyeqBE3Tsqk1M6aQFo-8xy8kQ_bT7pdL9xh9w1UZ_kFg5pBMsaPk\",\"e\":\"AQAB\",\"d\":\""
"ANWOxOPXBPhH4bu18FGu7ojPc62l6ykrLPa26QN6hVhFOvShG-2mzhgoFO4Z23G1WhvIEdbz8NU9WbGAE"
"ZVnpXx_pFhyLUCNndwx0xFfuYgUeueDO0pt7vSzdCeeeJK8VLWRcxxStahiLgUgvnts0dskZfWEOjLG59"
"0rpemwadzdSGK44zgRhJQ1gr0PrsWoqZXWKT9OE5PwMQwL5cnN3GvXX2-PnxLUnjXzK9VN6nKl0dP67HK"
"rBcrHZ4HXbLAoc1BjStidW1MmESNWPBkcnq-yKjmkrXzMbTH0ufJY1zYu6obdgLYDDN_QJgR4w3sXS2tN"
"BRMj0XCmgFkAknD7mAE\",\"p\":\"AOoXE9yq9elQvRJ1bV0EjEfa1D1c0eubEHjStluxKA37QnpqAKL"
"vMv44DiGdbFAewvkE8gP6Yjv-ls8ynvcJuYjcDyUnN2jjPaYKOopaqoejq0LQJtXGHiPUX5929y-5uDAu"
"e0Mu5C2x3_uv0MXZS316-9oIK0ooszurC6tkvDTZ\",\"q\":\"AP5iyitBD-0YUnQ4VIakwWaOx6wtLt"
"GuQgTu3o1hneo9rIY5MwvSSfT2PmkjGqFRzhQTv504roz8J2kSSzurV32JGer9H7db45afiDBl_UiEbds"
"X_LKScOYGgWnm8yDm2YY_UzwbmD4H0xCDUYszbSSfYiVpBvZIe2sKpOK4YsEh\",\"qi\":\"AMULGD_n"
"LWXAfOa_-dtQRP7yXENDQtKMwsTQrVrQgCynH0EVGWEUyPXA8PsHtzUiR_bLNGpdDgiMnfiEvXuv-Y_y9"
"kzUCDi9RtA8tzTTq6EUR_YK0MJd4yiRYOnK0OAXTyTQPPlS-pUWk0J9l4p4uxTJe0m7J418naPLS9l7Xf"
"kd\",\"dp\":\"AId1u0SimZLd6ctYsGR3UUXzV4X6xG72WF3ScTw2E9ujXiDAXoXqrTN29JZ3JkpmwqS"
"fO_0ZUucst9BGlr6VnguYbBsvylyjwvTmTmHpfWzoRR5wnUhvUNmi94KrsPapHfCjtSh3ZgsbN2XJo6IZ"
"0BlYpYzR1VsgmjcZD7Oqo05h\",\"dq\":\"ALHiWwUMJhrhmybyDQlqRGN3DGF15vtxI3FXqACtdkPKh"
"M4HSY7GqjjFyLa0eXa9QaIAfUlvzX-BA_4RcNJ06mU6bglIn9kURH2baRyO9SK0mC1RBL_Kb3AqtGxdtz"
"4Wr52UwpuRoFAgIJO3gFoayAOIAJWwb9HgtY0QkGSKE2SB\",\"kid\":\"" KID_1 "\"},{\"kty\":\"RS"
"A\",\"n\":\"AMZGRVyWHvHCkbGpGF6xdhKSjYwX1q5xtS-9_rATkpGyp5f-vCl9uUgdD0CZZIuuEvWsR"
"vp1zt-JZVS9GrnoWBLZXzafHKO4pADMPPGlzaBsEmp4E5S7t6c4LGMgXExDoBs8jbp3TwbUeiyIsHyQzl"
"Y5pfg8_2Stp-PtoOWBVpWvhp1uxVuvvIp5TfHK3q2q3Iziggvja-p_cLji95AAXOLBEfaRklMLPM0aMm9"
"96-dX7Yq-cUO5ptCBEoRBcPlEJjFP9ZY_Hb0_3W8BIpkvf_zTcGsgIrcx17mIp9yRQcQ9pQNSa5kpk3nf"
"v2BZ6tJHu8KfKsA3WesYOkMM_6VoFRk\",\"e\":\"AQAB\",\"d\":\"X3No5N-oWf6vIPYks0F_dAV1"
"eyHmyegXr7opqB5kCxwUromFj_vkfKDwvMqbqtrMadTb_qtEQjzkuVyoRyNhcwGOYr9KjE7RNUkddb-6N"
"CaS3wqbcpjEGw5h3_6uMFDF_RazrDbPppwXjOTpAa68hqoOCmljEda_4mx9br9LLZePk-g0L1YE62-ShM"
"_ThI-azzrCNodKc37j6jVZ8x3gYACM2vtJTc-o7EOO-00bjyDrOKlJGLB9lGTSbSOij-Ilzmd_S58ykku"
"I-t6VULFEjnPed46W_S7fsVkTBlHab6zGTFCMWSpj1_EVDXdH2IcGJ1UgrHTQyiYmmKUkIqv6mQ\",\"p"
"\":\"ANqoPnFPan_AhngjrRrxtbT5aTyGcqreyrkE9g4zgAFdaSYXkUbIRQXcmp9KvoYk3rXr2SYolWWe"
"IhpMIDKbUL6ZR6GXxQw_YcNVVY_haPCI0OyG-qMnVykYIcvgyAUeupZGT3gZaAdXR2BTxNqPepV-MIAIv"
"8DU7upttwHu06-H\",\"q\":\"AOgi46IPh9oogaCnlnN7iex3VmbTy1T97vtM9qGIDy-kCipBkfUJbXk"
"JnZ6LhSnoeeE5oKZn-CTriBXR4Bsjs7YiSUrEcNU5ZmBIs_56o6SyuniA71L3-bxfvHnwB5ysNFGKgKId"
"7Skfx7u9f-AEGs_qA7kQ1w714DbFQYE2Pv5f\",\"qi\":\"eU35yvBcZiZ2Jzs8UU9CT1uJ9z5OjT-hg"
"1QlkbQgPHQB1JhFsoMYqBsYpaUttwrCHbTJjW13-7fvEoFXS6RJm4qGg-LfY65LeCcF6djXr6XumqlJNM"
"lFWF8aK5AZIiSZ_HUn5mdNRwbiONgmFwYjv3_nqBIfrXJ3C55FR9CcvD4\",\"dp\":\"AMFROlPH2Oq1"
"9q1FLYjC5tnoIMioPb0gWK8X2ctYcPXD9nD9KS4hZhT2o6Xt2WCUPGsu57-65cr_8jq5z0Wu18aLki8mF"
"crsRq0CRzF8IuF2tPBJrlKNN5xXf5nXVEBimKi_5QbTv4ut-KcLqOFrNP_yn0KzeYUtPUX6VnDZDEMF\""
",\"dq\":\"AJnn_9pDx8N5VbBpTFPWlXRFDvDv_QClt5u_xEkGh2MDtIWdoaK_lGhKWslyIWDOtHgCGCQ"
"cDKaVzk0BMD9uJUldZBCBO3nzK5Asw8G2F-crZHxep83vgRFGvBRwcuuKNMnXNT_G7aV1X5x2oGCq-Aff"
"VIaPxrYxiG1nzO1ZRNyr\",\"kid\":\"" KID_2 "\",\"alg\":\"PS512\"},{\"kty\":\"EC\",\"x\":\"AJ6TXabOS7Blc_B"
"NQVqQgp1nEwmatr8g9_HlPaoP4MPe\",\"y\":\"ALbKJWr4c4tksiv2IMWbfq09gghvuaR1pO2S_QjjX"
"UtZ\",\"d\":\"Xk9lCflRiR6ErF1nqwSYhAFsOteufFotEi2z2xWDHks\",\"crv\":\"P-256\",\"k"
"id\":\"" KID_3 "\",\"alg\":\"ES384\"},{\"kty\":\"oct\",\"k\":\"Kt5w3prEDTYJn8IveV1JtjXvtlAX0WRSEcEHxmND"
"bP3aY760nHjA4VlCvxJQCYTSE1C1KObMmEnwjHrJzBedP-rqjn0SlzovvYyYWJL7Ujukqg4lhQxkLO5FZ"
"jBNy1_i1-J3jPbP-DccD31-Kbxxmudqzd9LFVobDGoNvf-DdkQ\",\"kid\":\"" KID_4 "\",\"alg\":\"HS256\"}]}";
const char jwks_privkey_alg_invalid[] = 
"{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AOidO2hPJFDK-jHdQ6p-SDGNAS3SbTCq1DN7Yv4kmClva"
"5FtgLFIG8VG0hvn8RKN2kpqmNOa30KsOlYW9GqUCy6esFn0yqyNC_01IVY67qPIU5SRbCD88UXSfqsnhN"
"sFgwU76OmpamqBGXUenZRrewNleNfYLJ6fNQO5n1rOa_UCcOaFqNLjjAcS9Z6e6h4Edlhz6ecYEVW6ZYF"
"ODRNmyq_Pf0nZGgUjKXuAzEb8GdhiO99TcsLoc7RxTbfsvqLGofPXhY5EfWksNyeqJtINUEtMC78nADM6"
"J_jFyeqBE3Tsqk1M6aQFo-8xy8kQ_bT7pdL9xh9w1UZ_kFg5pBMsaPk\",\"e\":\"AQAB\",\"d\":\""
"ANWOxOPXBPhH4bu18FGu7ojPc62l6ykrLPa26QN6hVhFOvShG-2mzhgoFO4Z23G1WhvIEdbz8NU9WbGAE"
"ZVnpXx_pFhyLUCNndwx0xFfuYgUeueDO0pt7vSzdCeeeJK8VLWRcxxStahiLgUgvnts0dskZfWEOjLG59"
"0rpemwadzdSGK44zgRhJQ1gr0PrsWoqZXWKT9OE5PwMQwL5cnN3GvXX2-PnxLUnjXzK9VN6nKl0dP67HK"
"rBcrHZ4HXbLAoc1BjStidW1MmESNWPBkcnq-yKjmkrXzMbTH0ufJY1zYu6obdgLYDDN_QJgR4w3sXS2tN"
"BRMj0XCmgFkAknD7mAE\",\"p\":\"AOoXE9yq9elQvRJ1bV0EjEfa1D1c0eubEHjStluxKA37QnpqAKL"
"vMv44DiGdbFAewvkE8gP6Yjv-ls8ynvcJuYjcDyUnN2jjPaYKOopaqoejq0LQJtXGHiPUX5929y-5uDAu"
"e0Mu5C2x3_uv0MXZS316-9oIK0ooszurC6tkvDTZ\",\"q\":\"AP5iyitBD-0YUnQ4VIakwWaOx6wtLt"
"GuQgTu3o1hneo9rIY5MwvSSfT2PmkjGqFRzhQTv504roz8J2kSSzurV32JGer9H7db45afiDBl_UiEbds"
"X_LKScOYGgWnm8yDm2YY_UzwbmD4H0xCDUYszbSSfYiVpBvZIe2sKpOK4YsEh\",\"qi\":\"AMULGD_n"
"LWXAfOa_-dtQRP7yXENDQtKMwsTQrVrQgCynH0EVGWEUyPXA8PsHtzUiR_bLNGpdDgiMnfiEvXuv-Y_y9"
"kzUCDi9RtA8tzTTq6EUR_YK0MJd4yiRYOnK0OAXTyTQPPlS-pUWk0J9l4p4uxTJe0m7J418naPLS9l7Xf"
"kd\",\"dp\":\"AId1u0SimZLd6ctYsGR3UUXzV4X6xG72WF3ScTw2E9ujXiDAXoXqrTN29JZ3JkpmwqS"
"fO_0ZUucst9BGlr6VnguYbBsvylyjwvTmTmHpfWzoRR5wnUhvUNmi94KrsPapHfCjtSh3ZgsbN2XJo6IZ"
"0BlYpYzR1VsgmjcZD7Oqo05h\",\"dq\":\"ALHiWwUMJhrhmybyDQlqRGN3DGF15vtxI3FXqACtdkPKh"
"M4HSY7GqjjFyLa0eXa9QaIAfUlvzX-BA_4RcNJ06mU6bglIn9kURH2baRyO9SK0mC1RBL_Kb3AqtGxdtz"
"4Wr52UwpuRoFAgIJO3gFoayAOIAJWwb9HgtY0QkGSKE2SB\",\"kid\":\"" KID_1 "\",\"alg\":\"error\"},{\"kty\":\"RS"
"A\",\"n\":\"AMZGRVyWHvHCkbGpGF6xdhKSjYwX1q5xtS-9_rATkpGyp5f-vCl9uUgdD0CZZIuuEvWsR"
"vp1zt-JZVS9GrnoWBLZXzafHKO4pADMPPGlzaBsEmp4E5S7t6c4LGMgXExDoBs8jbp3TwbUeiyIsHyQzl"
"Y5pfg8_2Stp-PtoOWBVpWvhp1uxVuvvIp5TfHK3q2q3Iziggvja-p_cLji95AAXOLBEfaRklMLPM0aMm9"
"96-dX7Yq-cUO5ptCBEoRBcPlEJjFP9ZY_Hb0_3W8BIpkvf_zTcGsgIrcx17mIp9yRQcQ9pQNSa5kpk3nf"
"v2BZ6tJHu8KfKsA3WesYOkMM_6VoFRk\",\"e\":\"AQAB\",\"d\":\"X3No5N-oWf6vIPYks0F_dAV1"
"eyHmyegXr7opqB5kCxwUromFj_vkfKDwvMqbqtrMadTb_qtEQjzkuVyoRyNhcwGOYr9KjE7RNUkddb-6N"
"CaS3wqbcpjEGw5h3_6uMFDF_RazrDbPppwXjOTpAa68hqoOCmljEda_4mx9br9LLZePk-g0L1YE62-ShM"
"_ThI-azzrCNodKc37j6jVZ8x3gYACM2vtJTc-o7EOO-00bjyDrOKlJGLB9lGTSbSOij-Ilzmd_S58ykku"
"I-t6VULFEjnPed46W_S7fsVkTBlHab6zGTFCMWSpj1_EVDXdH2IcGJ1UgrHTQyiYmmKUkIqv6mQ\",\"p"
"\":\"ANqoPnFPan_AhngjrRrxtbT5aTyGcqreyrkE9g4zgAFdaSYXkUbIRQXcmp9KvoYk3rXr2SYolWWe"
"IhpMIDKbUL6ZR6GXxQw_YcNVVY_haPCI0OyG-qMnVykYIcvgyAUeupZGT3gZaAdXR2BTxNqPepV-MIAIv"
"8DU7upttwHu06-H\",\"q\":\"AOgi46IPh9oogaCnlnN7iex3VmbTy1T97vtM9qGIDy-kCipBkfUJbXk"
"JnZ6LhSnoeeE5oKZn-CTriBXR4Bsjs7YiSUrEcNU5ZmBIs_56o6SyuniA71L3-bxfvHnwB5ysNFGKgKId"
"7Skfx7u9f-AEGs_qA7kQ1w714DbFQYE2Pv5f\",\"qi\":\"eU35yvBcZiZ2Jzs8UU9CT1uJ9z5OjT-hg"
"1QlkbQgPHQB1JhFsoMYqBsYpaUttwrCHbTJjW13-7fvEoFXS6RJm4qGg-LfY65LeCcF6djXr6XumqlJNM"
"lFWF8aK5AZIiSZ_HUn5mdNRwbiONgmFwYjv3_nqBIfrXJ3C55FR9CcvD4\",\"dp\":\"AMFROlPH2Oq1"
"9q1FLYjC5tnoIMioPb0gWK8X2ctYcPXD9nD9KS4hZhT2o6Xt2WCUPGsu57-65cr_8jq5z0Wu18aLki8mF"
"crsRq0CRzF8IuF2tPBJrlKNN5xXf5nXVEBimKi_5QbTv4ut-KcLqOFrNP_yn0KzeYUtPUX6VnDZDEMF\""
",\"dq\":\"AJnn_9pDx8N5VbBpTFPWlXRFDvDv_QClt5u_xEkGh2MDtIWdoaK_lGhKWslyIWDOtHgCGCQ"
"cDKaVzk0BMD9uJUldZBCBO3nzK5Asw8G2F-crZHxep83vgRFGvBRwcuuKNMnXNT_G7aV1X5x2oGCq-Aff"
"VIaPxrYxiG1nzO1ZRNyr\",\"kid\":\"" KID_2 "\",\"alg\":\"PS512\"},{\"kty\":\"EC\",\"x\":\"AJ6TXabOS7Blc_B"
"NQVqQgp1nEwmatr8g9_HlPaoP4MPe\",\"y\":\"ALbKJWr4c4tksiv2IMWbfq09gghvuaR1pO2S_QjjX"
"UtZ\",\"d\":\"Xk9lCflRiR6ErF1nqwSYhAFsOteufFotEi2z2xWDHks\",\"crv\":\"P-256\",\"k"
"id\":\"" KID_3 "\",\"alg\":\"ES384\"},{\"kty\":\"oct\",\"k\":\"Kt5w3prEDTYJn8IveV1JtjXvtlAX0WRSEcEHxmND"
"bP3aY760nHjA4VlCvxJQCYTSE1C1KObMmEnwjHrJzBedP-rqjn0SlzovvYyYWJL7Ujukqg4lhQxkLO5FZ"
"jBNy1_i1-J3jPbP-DccD31-Kbxxmudqzd9LFVobDGoNvf-DdkQ\",\"kid\":\"" KID_4 "\",\"alg\":\"HS256\"}]}";
const char jwks_privkey_kid_missing[] = 
"{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AOidO2hPJFDK-jHdQ6p-SDGNAS3SbTCq1DN7Yv4kmClva"
"5FtgLFIG8VG0hvn8RKN2kpqmNOa30KsOlYW9GqUCy6esFn0yqyNC_01IVY67qPIU5SRbCD88UXSfqsnhN"
"sFgwU76OmpamqBGXUenZRrewNleNfYLJ6fNQO5n1rOa_UCcOaFqNLjjAcS9Z6e6h4Edlhz6ecYEVW6ZYF"
"ODRNmyq_Pf0nZGgUjKXuAzEb8GdhiO99TcsLoc7RxTbfsvqLGofPXhY5EfWksNyeqJtINUEtMC78nADM6"
"J_jFyeqBE3Tsqk1M6aQFo-8xy8kQ_bT7pdL9xh9w1UZ_kFg5pBMsaPk\",\"e\":\"AQAB\",\"d\":\""
"ANWOxOPXBPhH4bu18FGu7ojPc62l6ykrLPa26QN6hVhFOvShG-2mzhgoFO4Z23G1WhvIEdbz8NU9WbGAE"
"ZVnpXx_pFhyLUCNndwx0xFfuYgUeueDO0pt7vSzdCeeeJK8VLWRcxxStahiLgUgvnts0dskZfWEOjLG59"
"0rpemwadzdSGK44zgRhJQ1gr0PrsWoqZXWKT9OE5PwMQwL5cnN3GvXX2-PnxLUnjXzK9VN6nKl0dP67HK"
"rBcrHZ4HXbLAoc1BjStidW1MmESNWPBkcnq-yKjmkrXzMbTH0ufJY1zYu6obdgLYDDN_QJgR4w3sXS2tN"
"BRMj0XCmgFkAknD7mAE\",\"p\":\"AOoXE9yq9elQvRJ1bV0EjEfa1D1c0eubEHjStluxKA37QnpqAKL"
"vMv44DiGdbFAewvkE8gP6Yjv-ls8ynvcJuYjcDyUnN2jjPaYKOopaqoejq0LQJtXGHiPUX5929y-5uDAu"
"e0Mu5C2x3_uv0MXZS316-9oIK0ooszurC6tkvDTZ\",\"q\":\"AP5iyitBD-0YUnQ4VIakwWaOx6wtLt"
"GuQgTu3o1hneo9rIY5MwvSSfT2PmkjGqFRzhQTv504roz8J2kSSzurV32JGer9H7db45afiDBl_UiEbds"
"X_LKScOYGgWnm8yDm2YY_UzwbmD4H0xCDUYszbSSfYiVpBvZIe2sKpOK4YsEh\",\"qi\":\"AMULGD_n"
"LWXAfOa_-dtQRP7yXENDQtKMwsTQrVrQgCynH0EVGWEUyPXA8PsHtzUiR_bLNGpdDgiMnfiEvXuv-Y_y9"
"kzUCDi9RtA8tzTTq6EUR_YK0MJd4yiRYOnK0OAXTyTQPPlS-pUWk0J9l4p4uxTJe0m7J418naPLS9l7Xf"
"kd\",\"dp\":\"AId1u0SimZLd6ctYsGR3UUXzV4X6xG72WF3ScTw2E9ujXiDAXoXqrTN29JZ3JkpmwqS"
"fO_0ZUucst9BGlr6VnguYbBsvylyjwvTmTmHpfWzoRR5wnUhvUNmi94KrsPapHfCjtSh3ZgsbN2XJo6IZ"
"0BlYpYzR1VsgmjcZD7Oqo05h\",\"dq\":\"ALHiWwUMJhrhmybyDQlqRGN3DGF15vtxI3FXqACtdkPKh"
"M4HSY7GqjjFyLa0eXa9QaIAfUlvzX-BA_4RcNJ06mU6bglIn9kURH2baRyO9SK0mC1RBL_Kb3AqtGxdtz"
"4Wr52UwpuRoFAgIJO3gFoayAOIAJWwb9HgtY0QkGSKE2SB\",\"alg\":\"RS256\"},{\"kty\":\"RS"
"A\",\"n\":\"AMZGRVyWHvHCkbGpGF6xdhKSjYwX1q5xtS-9_rATkpGyp5f-vCl9uUgdD0CZZIuuEvWsR"
"vp1zt-JZVS9GrnoWBLZXzafHKO4pADMPPGlzaBsEmp4E5S7t6c4LGMgXExDoBs8jbp3TwbUeiyIsHyQzl"
"Y5pfg8_2Stp-PtoOWBVpWvhp1uxVuvvIp5TfHK3q2q3Iziggvja-p_cLji95AAXOLBEfaRklMLPM0aMm9"
"96-dX7Yq-cUO5ptCBEoRBcPlEJjFP9ZY_Hb0_3W8BIpkvf_zTcGsgIrcx17mIp9yRQcQ9pQNSa5kpk3nf"
"v2BZ6tJHu8KfKsA3WesYOkMM_6VoFRk\",\"e\":\"AQAB\",\"d\":\"X3No5N-oWf6vIPYks0F_dAV1"
"eyHmyegXr7opqB5kCxwUromFj_vkfKDwvMqbqtrMadTb_qtEQjzkuVyoRyNhcwGOYr9KjE7RNUkddb-6N"
"CaS3wqbcpjEGw5h3_6uMFDF_RazrDbPppwXjOTpAa68hqoOCmljEda_4mx9br9LLZePk-g0L1YE62-ShM"
"_ThI-azzrCNodKc37j6jVZ8x3gYACM2vtJTc-o7EOO-00bjyDrOKlJGLB9lGTSbSOij-Ilzmd_S58ykku"
"I-t6VULFEjnPed46W_S7fsVkTBlHab6zGTFCMWSpj1_EVDXdH2IcGJ1UgrHTQyiYmmKUkIqv6mQ\",\"p"
"\":\"ANqoPnFPan_AhngjrRrxtbT5aTyGcqreyrkE9g4zgAFdaSYXkUbIRQXcmp9KvoYk3rXr2SYolWWe"
"IhpMIDKbUL6ZR6GXxQw_YcNVVY_haPCI0OyG-qMnVykYIcvgyAUeupZGT3gZaAdXR2BTxNqPepV-MIAIv"
"8DU7upttwHu06-H\",\"q\":\"AOgi46IPh9oogaCnlnN7iex3VmbTy1T97vtM9qGIDy-kCipBkfUJbXk"
"JnZ6LhSnoeeE5oKZn-CTriBXR4Bsjs7YiSUrEcNU5ZmBIs_56o6SyuniA71L3-bxfvHnwB5ysNFGKgKId"
"7Skfx7u9f-AEGs_qA7kQ1w714DbFQYE2Pv5f\",\"qi\":\"eU35yvBcZiZ2Jzs8UU9CT1uJ9z5OjT-hg"
"1QlkbQgPHQB1JhFsoMYqBsYpaUttwrCHbTJjW13-7fvEoFXS6RJm4qGg-LfY65LeCcF6djXr6XumqlJNM"
"lFWF8aK5AZIiSZ_HUn5mdNRwbiONgmFwYjv3_nqBIfrXJ3C55FR9CcvD4\",\"dp\":\"AMFROlPH2Oq1"
"9q1FLYjC5tnoIMioPb0gWK8X2ctYcPXD9nD9KS4hZhT2o6Xt2WCUPGsu57-65cr_8jq5z0Wu18aLki8mF"
"crsRq0CRzF8IuF2tPBJrlKNN5xXf5nXVEBimKi_5QbTv4ut-KcLqOFrNP_yn0KzeYUtPUX6VnDZDEMF\""
",\"dq\":\"AJnn_9pDx8N5VbBpTFPWlXRFDvDv_QClt5u_xEkGh2MDtIWdoaK_lGhKWslyIWDOtHgCGCQ"
"cDKaVzk0BMD9uJUldZBCBO3nzK5Asw8G2F-crZHxep83vgRFGvBRwcuuKNMnXNT_G7aV1X5x2oGCq-Aff"
"VIaPxrYxiG1nzO1ZRNyr\",\"kid\":\"" KID_2 "\",\"alg\":\"PS512\"},{\"kty\":\"EC\",\"x\":\"AJ6TXabOS7Blc_B"
"NQVqQgp1nEwmatr8g9_HlPaoP4MPe\",\"y\":\"ALbKJWr4c4tksiv2IMWbfq09gghvuaR1pO2S_QjjX"
"UtZ\",\"d\":\"Xk9lCflRiR6ErF1nqwSYhAFsOteufFotEi2z2xWDHks\",\"crv\":\"P-256\",\"k"
"id\":\"" KID_3 "\",\"alg\":\"ES384\"},{\"kty\":\"oct\",\"k\":\"Kt5w3prEDTYJn8IveV1JtjXvtlAX0WRSEcEHxmND"
"bP3aY760nHjA4VlCvxJQCYTSE1C1KObMmEnwjHrJzBedP-rqjn0SlzovvYyYWJL7Ujukqg4lhQxkLO5FZ"
"jBNy1_i1-J3jPbP-DccD31-Kbxxmudqzd9LFVobDGoNvf-DdkQ\",\"kid\":\"" KID_4 "\",\"alg\":\"HS256\"}]}";
const char jwks_privkey_kid_invalid[] = 
"{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AOidO2hPJFDK-jHdQ6p-SDGNAS3SbTCq1DN7Yv4kmClva"
"5FtgLFIG8VG0hvn8RKN2kpqmNOa30KsOlYW9GqUCy6esFn0yqyNC_01IVY67qPIU5SRbCD88UXSfqsnhN"
"sFgwU76OmpamqBGXUenZRrewNleNfYLJ6fNQO5n1rOa_UCcOaFqNLjjAcS9Z6e6h4Edlhz6ecYEVW6ZYF"
"ODRNmyq_Pf0nZGgUjKXuAzEb8GdhiO99TcsLoc7RxTbfsvqLGofPXhY5EfWksNyeqJtINUEtMC78nADM6"
"J_jFyeqBE3Tsqk1M6aQFo-8xy8kQ_bT7pdL9xh9w1UZ_kFg5pBMsaPk\",\"e\":\"AQAB\",\"d\":\""
"ANWOxOPXBPhH4bu18FGu7ojPc62l6ykrLPa26QN6hVhFOvShG-2mzhgoFO4Z23G1WhvIEdbz8NU9WbGAE"
"ZVnpXx_pFhyLUCNndwx0xFfuYgUeueDO0pt7vSzdCeeeJK8VLWRcxxStahiLgUgvnts0dskZfWEOjLG59"
"0rpemwadzdSGK44zgRhJQ1gr0PrsWoqZXWKT9OE5PwMQwL5cnN3GvXX2-PnxLUnjXzK9VN6nKl0dP67HK"
"rBcrHZ4HXbLAoc1BjStidW1MmESNWPBkcnq-yKjmkrXzMbTH0ufJY1zYu6obdgLYDDN_QJgR4w3sXS2tN"
"BRMj0XCmgFkAknD7mAE\",\"p\":\"AOoXE9yq9elQvRJ1bV0EjEfa1D1c0eubEHjStluxKA37QnpqAKL"
"vMv44DiGdbFAewvkE8gP6Yjv-ls8ynvcJuYjcDyUnN2jjPaYKOopaqoejq0LQJtXGHiPUX5929y-5uDAu"
"e0Mu5C2x3_uv0MXZS316-9oIK0ooszurC6tkvDTZ\",\"q\":\"AP5iyitBD-0YUnQ4VIakwWaOx6wtLt"
"GuQgTu3o1hneo9rIY5MwvSSfT2PmkjGqFRzhQTv504roz8J2kSSzurV32JGer9H7db45afiDBl_UiEbds"
"X_LKScOYGgWnm8yDm2YY_UzwbmD4H0xCDUYszbSSfYiVpBvZIe2sKpOK4YsEh\",\"qi\":\"AMULGD_n"
"LWXAfOa_-dtQRP7yXENDQtKMwsTQrVrQgCynH0EVGWEUyPXA8PsHtzUiR_bLNGpdDgiMnfiEvXuv-Y_y9"
"kzUCDi9RtA8tzTTq6EUR_YK0MJd4yiRYOnK0OAXTyTQPPlS-pUWk0J9l4p4uxTJe0m7J418naPLS9l7Xf"
"kd\",\"dp\":\"AId1u0SimZLd6ctYsGR3UUXzV4X6xG72WF3ScTw2E9ujXiDAXoXqrTN29JZ3JkpmwqS"
"fO_0ZUucst9BGlr6VnguYbBsvylyjwvTmTmHpfWzoRR5wnUhvUNmi94KrsPapHfCjtSh3ZgsbN2XJo6IZ"
"0BlYpYzR1VsgmjcZD7Oqo05h\",\"dq\":\"ALHiWwUMJhrhmybyDQlqRGN3DGF15vtxI3FXqACtdkPKh"
"M4HSY7GqjjFyLa0eXa9QaIAfUlvzX-BA_4RcNJ06mU6bglIn9kURH2baRyO9SK0mC1RBL_Kb3AqtGxdtz"
"4Wr52UwpuRoFAgIJO3gFoayAOIAJWwb9HgtY0QkGSKE2SB\",\"kid\":42,\"alg\":\"RS256\"},{\"kty\":\"RS"
"A\",\"n\":\"AMZGRVyWHvHCkbGpGF6xdhKSjYwX1q5xtS-9_rATkpGyp5f-vCl9uUgdD0CZZIuuEvWsR"
"vp1zt-JZVS9GrnoWBLZXzafHKO4pADMPPGlzaBsEmp4E5S7t6c4LGMgXExDoBs8jbp3TwbUeiyIsHyQzl"
"Y5pfg8_2Stp-PtoOWBVpWvhp1uxVuvvIp5TfHK3q2q3Iziggvja-p_cLji95AAXOLBEfaRklMLPM0aMm9"
"96-dX7Yq-cUO5ptCBEoRBcPlEJjFP9ZY_Hb0_3W8BIpkvf_zTcGsgIrcx17mIp9yRQcQ9pQNSa5kpk3nf"
"v2BZ6tJHu8KfKsA3WesYOkMM_6VoFRk\",\"e\":\"AQAB\",\"d\":\"X3No5N-oWf6vIPYks0F_dAV1"
"eyHmyegXr7opqB5kCxwUromFj_vkfKDwvMqbqtrMadTb_qtEQjzkuVyoRyNhcwGOYr9KjE7RNUkddb-6N"
"CaS3wqbcpjEGw5h3_6uMFDF_RazrDbPppwXjOTpAa68hqoOCmljEda_4mx9br9LLZePk-g0L1YE62-ShM"
"_ThI-azzrCNodKc37j6jVZ8x3gYACM2vtJTc-o7EOO-00bjyDrOKlJGLB9lGTSbSOij-Ilzmd_S58ykku"
"I-t6VULFEjnPed46W_S7fsVkTBlHab6zGTFCMWSpj1_EVDXdH2IcGJ1UgrHTQyiYmmKUkIqv6mQ\",\"p"
"\":\"ANqoPnFPan_AhngjrRrxtbT5aTyGcqreyrkE9g4zgAFdaSYXkUbIRQXcmp9KvoYk3rXr2SYolWWe"
"IhpMIDKbUL6ZR6GXxQw_YcNVVY_haPCI0OyG-qMnVykYIcvgyAUeupZGT3gZaAdXR2BTxNqPepV-MIAIv"
"8DU7upttwHu06-H\",\"q\":\"AOgi46IPh9oogaCnlnN7iex3VmbTy1T97vtM9qGIDy-kCipBkfUJbXk"
"JnZ6LhSnoeeE5oKZn-CTriBXR4Bsjs7YiSUrEcNU5ZmBIs_56o6SyuniA71L3-bxfvHnwB5ysNFGKgKId"
"7Skfx7u9f-AEGs_qA7kQ1w714DbFQYE2Pv5f\",\"qi\":\"eU35yvBcZiZ2Jzs8UU9CT1uJ9z5OjT-hg"
"1QlkbQgPHQB1JhFsoMYqBsYpaUttwrCHbTJjW13-7fvEoFXS6RJm4qGg-LfY65LeCcF6djXr6XumqlJNM"
"lFWF8aK5AZIiSZ_HUn5mdNRwbiONgmFwYjv3_nqBIfrXJ3C55FR9CcvD4\",\"dp\":\"AMFROlPH2Oq1"
"9q1FLYjC5tnoIMioPb0gWK8X2ctYcPXD9nD9KS4hZhT2o6Xt2WCUPGsu57-65cr_8jq5z0Wu18aLki8mF"
"crsRq0CRzF8IuF2tPBJrlKNN5xXf5nXVEBimKi_5QbTv4ut-KcLqOFrNP_yn0KzeYUtPUX6VnDZDEMF\""
",\"dq\":\"AJnn_9pDx8N5VbBpTFPWlXRFDvDv_QClt5u_xEkGh2MDtIWdoaK_lGhKWslyIWDOtHgCGCQ"
"cDKaVzk0BMD9uJUldZBCBO3nzK5Asw8G2F-crZHxep83vgRFGvBRwcuuKNMnXNT_G7aV1X5x2oGCq-Aff"
"VIaPxrYxiG1nzO1ZRNyr\",\"kid\":\"" KID_2 "\",\"alg\":\"PS512\"},{\"kty\":\"EC\",\"x\":\"AJ6TXabOS7Blc_B"
"NQVqQgp1nEwmatr8g9_HlPaoP4MPe\",\"y\":\"ALbKJWr4c4tksiv2IMWbfq09gghvuaR1pO2S_QjjX"
"UtZ\",\"d\":\"Xk9lCflRiR6ErF1nqwSYhAFsOteufFotEi2z2xWDHks\",\"crv\":\"P-256\",\"k"
"id\":\"" KID_3 "\",\"alg\":\"ES384\"},{\"kty\":\"oct\",\"k\":\"Kt5w3prEDTYJn8IveV1JtjXvtlAX0WRSEcEHxmND"
"bP3aY760nHjA4VlCvxJQCYTSE1C1KObMmEnwjHrJzBedP-rqjn0SlzovvYyYWJL7Ujukqg4lhQxkLO5FZ"
"jBNy1_i1-J3jPbP-DccD31-Kbxxmudqzd9LFVobDGoNvf-DdkQ\",\"kid\":\"" KID_4 "\",\"alg\":\"HS256\"}]}";
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

struct _u_request admin_req;
struct _u_request user_req;

static int callback_request_jwks_invalid_json (const struct _u_request * request, struct _u_response * response, void * user_data) {
  ulfius_set_string_body_response(response, 200, jwks_privkey);
  return U_CALLBACK_COMPLETE;
}

static int callback_request_jwks_alg_invalid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * jwks = json_loads(jwks_privkey_alg_invalid, JSON_DECODE_ANY, NULL);
  ulfius_set_json_body_response(response, 200, jwks);
  json_decref(jwks);
  return U_CALLBACK_COMPLETE;
}

static int callback_request_jwks_valid (const struct _u_request * request, struct _u_response * response, void * user_data) {
  json_t * jwks = json_loads(jwks_privkey, JSON_DECODE_ANY, NULL);
  ulfius_set_json_body_response(response, 200, jwks);
  json_decref(jwks);
  return U_CALLBACK_COMPLETE;
}

START_TEST(test_oidc_jwks_add_module_alg_missing)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssisisisososososososososososisssssssossssssssssssssssss}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwks-private", jwks_privkey_alg_missing,
                                  "default-kid", KID_1,
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
                                  "encrypt-out-token-allow", json_true(),
                                  "client-enc-parameter", "enc",
                                  "client-alg-parameter", "alg",
                                  "client-alg_kid-parameter", "alg_kid",
                                  "client-sign_kid-parameter", "sign_kid",
                                  "client-encrypt_code-parameter", "encrypt_code",
                                  "client-encrypt_at-parameter", "encrypt_at",
                                  "client-encrypt_userinfo-parameter", "encrypt_userinfo",
                                  "client-encrypt_id_token-parameter", "encrypt_id_token",
                                  "client-encrypt_refresh_token-parameter", "encrypt_refresh_token");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_jwks_add_module_alg_invalid)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssisisisososososososososososisssssssossssssssssssssssss}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwks-private", jwks_privkey_alg_invalid,
                                  "default-kid", KID_1,
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
                                  "encrypt-out-token-allow", json_true(),
                                  "client-enc-parameter", "enc",
                                  "client-alg-parameter", "alg",
                                  "client-alg_kid-parameter", "alg_kid",
                                  "client-sign_kid-parameter", "sign_kid",
                                  "client-encrypt_code-parameter", "encrypt_code",
                                  "client-encrypt_at-parameter", "encrypt_at",
                                  "client-encrypt_userinfo-parameter", "encrypt_userinfo",
                                  "client-encrypt_id_token-parameter", "encrypt_id_token",
                                  "client-encrypt_refresh_token-parameter", "encrypt_refresh_token");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_jwks_add_module_kid_missing)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssisisisososososososososososisssssssossssssssssssssssss}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwks-private", jwks_privkey_kid_missing,
                                  "default-kid", KID_1,
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
                                  "encrypt-out-token-allow", json_true(),
                                  "client-enc-parameter", "enc",
                                  "client-alg-parameter", "alg",
                                  "client-alg_kid-parameter", "alg_kid",
                                  "client-sign_kid-parameter", "sign_kid",
                                  "client-encrypt_code-parameter", "encrypt_code",
                                  "client-encrypt_at-parameter", "encrypt_at",
                                  "client-encrypt_userinfo-parameter", "encrypt_userinfo",
                                  "client-encrypt_id_token-parameter", "encrypt_id_token",
                                  "client-encrypt_refresh_token-parameter", "encrypt_refresh_token");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_jwks_add_module_kid_invalid)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssisisisososososososososososisssssssossssssssssssssssss}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwks-private", jwks_privkey_kid_invalid,
                                  "default-kid", KID_1,
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
                                  "encrypt-out-token-allow", json_true(),
                                  "client-enc-parameter", "enc",
                                  "client-alg-parameter", "alg",
                                  "client-alg_kid-parameter", "alg_kid",
                                  "client-sign_kid-parameter", "sign_kid",
                                  "client-encrypt_code-parameter", "encrypt_code",
                                  "client-encrypt_at-parameter", "encrypt_at",
                                  "client-encrypt_userinfo-parameter", "encrypt_userinfo",
                                  "client-encrypt_id_token-parameter", "encrypt_id_token",
                                  "client-encrypt_refresh_token-parameter", "encrypt_refresh_token");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_jwks_add_module_uri_invalid_json)
{
  struct _u_instance instance;
  ulfius_init_instance(&instance, 7597, NULL, NULL);
  ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/jwks", 0, &callback_request_jwks_invalid_json, NULL);
  ulfius_start_framework(&instance);

  json_t * j_parameters = json_pack("{sssssssos{sssssssisisisososososososososososisssssssossssssssssssssssss}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwks-uri", "http://localhost:7597/jwks",
                                  "default-kid", KID_1,
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
                                  "encrypt-out-token-allow", json_true(),
                                  "client-enc-parameter", "enc",
                                  "client-alg-parameter", "alg",
                                  "client-alg_kid-parameter", "alg_kid",
                                  "client-sign_kid-parameter", "sign_kid",
                                  "client-encrypt_code-parameter", "encrypt_code",
                                  "client-encrypt_at-parameter", "encrypt_at",
                                  "client-encrypt_userinfo-parameter", "encrypt_userinfo",
                                  "client-encrypt_id_token-parameter", "encrypt_id_token",
                                  "client-encrypt_refresh_token-parameter", "encrypt_refresh_token");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_oidc_jwks_add_module_uri_invalid)
{
  struct _u_instance instance;
  ulfius_init_instance(&instance, 7598, NULL, NULL);
  ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/jwks", 0, &callback_request_jwks_alg_invalid, NULL);
  ulfius_start_framework(&instance);

  json_t * j_parameters = json_pack("{sssssssos{sssssssisisisososososososososososisssssssossssssssssssssssss}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwks-uri", "http://localhost:7598/jwks",
                                  "default-kid", KID_1,
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
                                  "encrypt-out-token-allow", json_true(),
                                  "client-enc-parameter", "enc",
                                  "client-alg-parameter", "alg",
                                  "client-alg_kid-parameter", "alg_kid",
                                  "client-sign_kid-parameter", "sign_kid",
                                  "client-encrypt_code-parameter", "encrypt_code",
                                  "client-encrypt_at-parameter", "encrypt_at",
                                  "client-encrypt_userinfo-parameter", "encrypt_userinfo",
                                  "client-encrypt_id_token-parameter", "encrypt_id_token",
                                  "client-encrypt_refresh_token-parameter", "encrypt_refresh_token");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 400, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_oidc_jwks_add_module_uri_valid)
{
  struct _u_instance instance;
  ulfius_init_instance(&instance, 7599, NULL, NULL);
  ulfius_add_endpoint_by_val(&instance, "GET", NULL, "/jwks", 0, &callback_request_jwks_valid, NULL);
  ulfius_start_framework(&instance);

  json_t * j_parameters = json_pack("{sssssssos{sssssssisisisososososososososososisssssssossssssssssssssssss}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwks-uri", "http://localhost:7599/jwks",
                                  "default-kid", KID_1,
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
                                  "encrypt-out-token-allow", json_true(),
                                  "client-enc-parameter", "enc",
                                  "client-alg-parameter", "alg",
                                  "client-alg_kid-parameter", "alg_kid",
                                  "client-sign_kid-parameter", "sign_kid",
                                  "client-encrypt_code-parameter", "encrypt_code",
                                  "client-encrypt_at-parameter", "encrypt_at",
                                  "client-encrypt_userinfo-parameter", "encrypt_userinfo",
                                  "client-encrypt_id_token-parameter", "encrypt_id_token",
                                  "client-encrypt_refresh_token-parameter", "encrypt_refresh_token");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
  ulfius_stop_framework(&instance);
  ulfius_clean_instance(&instance);
}
END_TEST

START_TEST(test_oidc_jwks_add_module_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssisisisososososososososososisssssssossssssssssssssssss}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwks-private", jwks_privkey,
                                  "default-kid", KID_1,
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
                                  "encrypt-out-token-allow", json_true(),
                                  "client-enc-parameter", "enc",
                                  "client-alg-parameter", "alg",
                                  "client-alg_kid-parameter", "alg_kid",
                                  "client-sign_kid-parameter", "sign_kid",
                                  "client-encrypt_code-parameter", "encrypt_code",
                                  "client-encrypt_at-parameter", "encrypt_at",
                                  "client-encrypt_userinfo-parameter", "encrypt_userinfo",
                                  "client-encrypt_id_token-parameter", "encrypt_id_token",
                                  "client-encrypt_refresh_token-parameter", "encrypt_refresh_token");

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_jwks_delete_module)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_jwks_discovery_valid)
{
#if GNUTLS_VERSION_NUMBER >= 0x030600
  json_t * j_result = json_loads("{\"issuer\":\"https://glewlwyd.tld\",\"authorization_endpoint\":\"http://localhost:4593/api/oidc_jwks/auth\",\"token_endpoint\":\"http://localhost:4593/api/oidc_jwks/token\",\"userinfo_endpoint\":\"http://localhost:4593/api/oidc_jwks/userinfo\",\"jwks_uri\":\"http://localhost:4593/api/oidc_jwks/jwks\",\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\"],\"id_token_signing_alg_values_supported\":[\"RS256\",\"PS512\",\"ES384\",\"HS256\"],\"userinfo_signing_alg_values_supported\":[\"RS256\",\"PS512\",\"ES384\",\"HS256\"],\"userinfo_encryption_alg_values_supported\":[\"RSA1_5\",\"A128KW\",\"A256KW\",\"dir\"],\"userinfo_encryption_enc_values_supported\":[\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\",\"A128GCM\",\"A256GCM\"],\"request_object_signing_alg_values_supported\":[\"none\",\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"EdDSA\",\"PS256\",\"PS384\",\"PS512\"],\"request_object_encryption_alg_values_supported\":[\"RSA1_5\",\"A128KW\",\"A256KW\",\"dir\"],\"request_object_encryption_enc_values_supported\":[\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\",\"A128GCM\",\"A256GCM\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"EdDSA\",\"PS256\",\"PS384\",\"PS512\"],\"scopes_supported\":[\"openid\"],\"response_types_supported\":[\"code\",\"id_token\",\"token id_token\",\"code id_token\",\"code token id_token\",\"password\",\"token\",\"client_credentials\",\"refresh_token\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],\"grant_types_supported\":[\"authorization_code\",\"implicit\"],\"display_values_supported\":[\"page\",\"popup\",\"touch\",\"wap\"],\"claim_types_supported\":[\"normal\"],\"claims_parameter_supported\":true,\"claims_supported\":[],\"ui_locales_supported\":[\"en\",\"fr\",\"nl\"],\"request_parameter_supported\":true,\"request_uri_parameter_supported\":true,\"require_request_uri_registration\":false,\"subject_types_supported\":[\"public\"]}", JSON_DECODE_ANY, NULL),
#else
  json_t * j_result = json_loads("{\"issuer\":\"https://glewlwyd.tld\",\"authorization_endpoint\":\"http://localhost:4593/api/oidc_jwks/auth\",\"token_endpoint\":\"http://localhost:4593/api/oidc_jwks/token\",\"userinfo_endpoint\":\"http://localhost:4593/api/oidc_jwks/userinfo\",\"jwks_uri\":\"http://localhost:4593/api/oidc_jwks/jwks\",\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\",\"client_secret_jwt\",\"private_key_jwt\"],\"id_token_signing_alg_values_supported\":[\"RS256\",\"PS512\",\"ES384\",\"HS256\"],\"userinfo_signing_alg_values_supported\":[\"RS256\",\"PS512\",\"ES384\",\"HS256\"],\"userinfo_encryption_alg_values_supported\":[\"RSA1_5\",\"A128KW\",\"A256KW\",\"dir\"],\"userinfo_encryption_enc_values_supported\":[\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\",\"A128GCM\",\"A256GCM\"],\"request_object_signing_alg_values_supported\":[\"none\",\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\"],\"request_object_encryption_alg_values_supported\":[\"RSA1_5\",\"A128KW\",\"A256KW\",\"dir\"],\"request_object_encryption_enc_values_supported\":[\"A128CBC-HS256\",\"A192CBC-HS384\",\"A256CBC-HS512\",\"A128GCM\",\"A256GCM\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\"],\"scopes_supported\":[\"openid\"],\"response_types_supported\":[\"code\",\"id_token\",\"token id_token\",\"code id_token\",\"code token id_token\",\"password\",\"token\",\"client_credentials\",\"refresh_token\"],\"response_modes_supported\":[\"query\",\"fragment\",\"form_post\"],\"grant_types_supported\":[\"authorization_code\",\"implicit\"],\"display_values_supported\":[\"page\",\"popup\",\"touch\",\"wap\"],\"claim_types_supported\":[\"normal\"],\"claims_parameter_supported\":true,\"claims_supported\":[],\"ui_locales_supported\":[\"en\",\"fr\",\"nl\"],\"request_parameter_supported\":true,\"request_uri_parameter_supported\":true,\"require_request_uri_registration\":false,\"subject_types_supported\":[\"public\"]}", JSON_DECODE_ANY, NULL),
#endif
  * j_key = json_loads("{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AOidO2hPJFDK-jHdQ6p-SDGNAS3SbTCq1DN7Yv4kmClva5FtgLFIG8VG0hvn8RKN2kpqmNOa30KsOlYW9GqUCy6esFn0yqyNC_01IVY67qPIU5SRbCD88UXSfqsnhNsFgwU76OmpamqBGXUenZRrewNleNfYLJ6fNQO5n1rOa_UCcOaFqNLjjAcS9Z6e6h4Edlhz6ecYEVW6ZYFODRNmyq_Pf0nZGgUjKXuAzEb8GdhiO99TcsLoc7RxTbfsvqLGofPXhY5EfWksNyeqJtINUEtMC78nADM6J_jFyeqBE3Tsqk1M6aQFo-8xy8kQ_bT7pdL9xh9w1UZ_kFg5pBMsaPk\",\"e\":\"AQAB\",\"kid\":\"key-1\"},{\"kty\":\"RSA\",\"n\":\"AMZGRVyWHvHCkbGpGF6xdhKSjYwX1q5xtS-9_rATkpGyp5f-vCl9uUgdD0CZZIuuEvWsRvp1zt-JZVS9GrnoWBLZXzafHKO4pADMPPGlzaBsEmp4E5S7t6c4LGMgXExDoBs8jbp3TwbUeiyIsHyQzlY5pfg8_2Stp-PtoOWBVpWvhp1uxVuvvIp5TfHK3q2q3Iziggvja-p_cLji95AAXOLBEfaRklMLPM0aMm996-dX7Yq-cUO5ptCBEoRBcPlEJjFP9ZY_Hb0_3W8BIpkvf_zTcGsgIrcx17mIp9yRQcQ9pQNSa5kpk3nfv2BZ6tJHu8KfKsA3WesYOkMM_6VoFRk\",\"e\":\"AQAB\",\"kid\":\"key-2\"},{\"kty\":\"EC\",\"x\":\"AJ6TXabOS7Blc_BNQVqQgp1nEwmatr8g9_HlPaoP4MPe\",\"y\":\"ALbKJWr4c4tksiv2IMWbfq09gghvuaR1pO2S_QjjXUtZ\",\"crv\":\"P-256\",\"kid\":\"key-3\"}]}", JSON_DECODE_ANY, NULL);
  
  ck_assert_ptr_ne(j_result, NULL);
  ck_assert_ptr_ne(j_key, NULL);
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/" PLUGIN_NAME "/.well-known/openid-configuration", NULL, NULL, NULL, NULL, 200, j_result, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(NULL, "GET", SERVER_URI "/" PLUGIN_NAME "/jwks", NULL, NULL, NULL, NULL, 200, j_key, NULL, NULL), 1);
  
  json_decref(j_result);
  json_decref(j_key);
}
END_TEST

START_TEST(test_oidc_jwks_add_client_sign_kid)
{
  json_t * j_client = json_pack("{ss ss ss so s[s] s[sssss] s[s] ss ss ss ss ss ss ss ss ss so}", "client_id", CLIENT_ID, "client_secret", CLIENT_SECRET, "name", CLIENT_NAME, "confidential", json_true(), "redirect_uri", CLIENT_REDIRECT, "authorization_type", "code", "token", "id_token", "password", "client_credentials", "scope", CLIENT_SCOPE, "sign_kid", KID_2, "pubkey", pubkey_1_pem, "enc", CLIENT_ENC, "alg", CLIENT_PUBKEY_ALG, "encrypt_code", "1", "encrypt_at", "nay", "encrypt_userinfo", "Hell no", "encrypt_id_token", "nope", "encrypt_refresh_token", "absolutely not!", "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_jwks_add_client_no_sign_kid)
{
  json_t * j_client = json_pack("{ss ss ss so s[s] s[sssss] s[s] ss ss ss ss ss ss ss ss so}", "client_id", CLIENT_ID, "client_secret", CLIENT_SECRET, "name", CLIENT_NAME, "confidential", json_true(), "redirect_uri", CLIENT_REDIRECT, "authorization_type", "code", "token", "id_token", "password", "client_credentials", "scope", CLIENT_SCOPE, "pubkey", pubkey_1_pem, "enc", CLIENT_ENC, "alg", CLIENT_PUBKEY_ALG, "encrypt_code", "1", "encrypt_at", "nay", "encrypt_userinfo", "Hell no", "encrypt_id_token", "nope", "encrypt_refresh_token", "absolutely not!", "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_jwks_add_client_invalid_sign_kid)
{
  json_t * j_client = json_pack("{ss ss ss so s[s] s[sssss] s[s] ss ss ss ss ss ss ss ss ss so}", "client_id", CLIENT_ID, "client_secret", CLIENT_SECRET, "name", CLIENT_NAME, "confidential", json_true(), "redirect_uri", CLIENT_REDIRECT, "authorization_type", "code", "token", "id_token", "password", "client_credentials", "scope", CLIENT_SCOPE, "sign_kid", "error", "pubkey", pubkey_1_pem, "enc", CLIENT_ENC, "alg", CLIENT_PUBKEY_ALG, "encrypt_code", "1", "encrypt_at", "nay", "encrypt_userinfo", "Hell no", "encrypt_id_token", "nope", "encrypt_refresh_token", "absolutely not!", "enabled", json_true());
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_client, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_client);

  json_t * j_param = json_pack("{ss}", "scope", SCOPE_LIST);
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
}
END_TEST

START_TEST(test_oidc_jwks_delete_client)
{
  json_t * j_param = json_pack("{ss}", "scope", "");
  ck_assert_int_eq(run_simple_test(&user_req, "PUT", SERVER_URI "/auth/grant/" CLIENT_ID, NULL, NULL, j_param, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_param);
  
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_jwks_implicit_id_token_valid_sign_kid)
{
  struct _u_response resp;
  char * id_token;
  jwt_t * jwt_idt;
  jwks_t * jwks_pub;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks_pub, SERVER_URI "/" PLUGIN_NAME "/jwks", 0), RHN_OK);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=")+o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *o_strchr(id_token, '&') = '\0';
  }
  ck_assert_int_eq(r_jwt_init(&jwt_idt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt_idt, id_token, 0), RHN_OK);
  ck_assert_int_eq(R_JWT_TYPE_SIGN, r_jwt_get_type(jwt_idt));
  ck_assert_str_eq(KID_2, r_jwt_get_header_str_value(jwt_idt, "kid"));
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_2), NULL);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt_idt, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(jwt_idt, NULL, 0), RHN_OK);
  
  o_free(id_token);
  r_jwt_free(jwt_idt);
  r_jwk_free(jwk);
  r_jwks_free(jwks_pub);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_jwks_userinfo_jwt_sign_kid)
{
  struct _u_response resp;
  struct _u_request req;
  char * access_token, * bearer;
  jwt_t * jwt;
  jwks_t * jwks_pub;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks_pub, SERVER_URI "/" PLUGIN_NAME "/jwks", 0), RHN_OK);
  
  ulfius_init_response(&resp);
  ulfius_init_request(&req);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  access_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "access_token=") + o_strlen("access_token="));
  if (o_strchr(access_token, '&')) {
    *(o_strchr(access_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(KID_2, r_jwt_get_header_str_value(jwt, "kid"));
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_2), NULL);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_OK);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  
  bearer = msprintf("Bearer %s", access_token);
  u_map_put(req.map_header, "Authorization", bearer);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/userinfo/");
  u_map_put(req.map_header, "Accept", "application/jwt");
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_str_eq(u_map_get(resp.map_header, "Content-Type"), "application/jwt");
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parsen(jwt, resp.binary_body, resp.binary_body_length, 0), RHN_OK);
  ck_assert_str_eq(KID_2, r_jwt_get_header_str_value(jwt, "kid"));
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_2), NULL);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_OK);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
  
  r_jwk_free(jwk);
  r_jwks_free(jwks_pub);
  ulfius_clean_request(&req);
  o_free(access_token);
  o_free(bearer);
}
END_TEST

START_TEST(test_oidc_jwks_client_cred_valid_sign_kid)
{
  struct _u_response resp;
  struct _u_request req;
  json_t * j_resp = NULL;
  jwt_t * jwt;
  jwks_t * jwks_pub;
  jwk_t * jwk;

  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks_pub, SERVER_URI "/" PLUGIN_NAME "/jwks", 0), RHN_OK);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "client_credentials");
  u_map_put(req.map_post_body, "scope", CLIENT_SCOPE);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(KID_2, r_jwt_get_header_str_value(jwt, "kid"));
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_2), NULL);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_OK);
  json_decref(j_resp);
  r_jwk_free(jwk);
  r_jwt_free(jwt);
  r_jwks_free(jwks_pub);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_jwks_implicit_id_token_valid_sign_kid_invalid)
{
  struct _u_response resp;
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "server_error"), NULL);

  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_jwks_client_cred_valid_sign_kid_invalid)
{
  struct _u_response resp;
  struct _u_request req;

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "client_credentials");
  u_map_put(req.map_post_body, "scope", CLIENT_SCOPE);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 500);
  
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_jwks_implicit_id_token_valid_no_sign_kid)
{
  struct _u_response resp;
  char * id_token;
  jwt_t * jwt_idt;
  jwks_t * jwks_pub;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks_pub, SERVER_URI "/" PLUGIN_NAME "/jwks", 0), RHN_OK);
  
  ulfius_init_response(&resp);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=id_token&g_continue&client_id=%s&redirect_uri=%s&state=xyzabcd&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  ck_assert_ptr_eq(o_strstr(u_map_get(resp.map_header, "Location"), "code="), NULL);
  id_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "id_token=")+o_strlen("id_token="));
  if (o_strchr(id_token, '&')) {
    *o_strchr(id_token, '&') = '\0';
  }
  ck_assert_int_eq(r_jwt_init(&jwt_idt), RHN_OK);
  
  ck_assert_int_eq(r_jwt_parse(jwt_idt, id_token, 0), RHN_OK);
  ck_assert_int_eq(R_JWT_TYPE_SIGN, r_jwt_get_type(jwt_idt));
  ck_assert_str_eq(KID_1, r_jwt_get_header_str_value(jwt_idt, "kid"));
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_1), NULL);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt_idt, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(jwt_idt, NULL, 0), RHN_OK);
  
  o_free(id_token);
  r_jwt_free(jwt_idt);
  r_jwk_free(jwk);
  r_jwks_free(jwks_pub);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_jwks_userinfo_jwt_no_sign_kid)
{
  struct _u_response resp;
  struct _u_request req;
  char * access_token, * bearer;
  jwt_t * jwt;
  jwks_t * jwks_pub;
  jwk_t * jwk;
  
  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks_pub, SERVER_URI "/" PLUGIN_NAME "/jwks", 0), RHN_OK);
  
  ulfius_init_response(&resp);
  ulfius_init_request(&req);
  o_free(user_req.http_url);
  user_req.http_url = msprintf("%s/%s/auth?response_type=token&g_continue&client_id=%s&redirect_uri=%s&nonce=nonce1234&scope=%s", SERVER_URI, PLUGIN_NAME, CLIENT_ID, CLIENT_REDIRECT, SCOPE_LIST);
  o_free(user_req.http_verb);
  user_req.http_verb = o_strdup("GET");
  ck_assert_int_eq(ulfius_send_http_request(&user_req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  access_token = o_strdup(o_strstr(u_map_get(resp.map_header, "Location"), "access_token=") + o_strlen("access_token="));
  if (o_strchr(access_token, '&')) {
    *(o_strchr(access_token, '&')) = '\0';
  }
  ulfius_clean_response(&resp);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, access_token, 0), RHN_OK);
  ck_assert_str_eq(KID_1, r_jwt_get_header_str_value(jwt, "kid"));
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_1), NULL);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_OK);
  r_jwt_free(jwt);
  r_jwk_free(jwk);
  
  bearer = msprintf("Bearer %s", access_token);
  u_map_put(req.map_header, "Authorization", bearer);

  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/userinfo/");
  u_map_put(req.map_header, "Accept", "application/jwt");
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_str_eq(u_map_get(resp.map_header, "Content-Type"), "application/jwt");
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parsen(jwt, resp.binary_body, resp.binary_body_length, 0), RHN_OK);
  ck_assert_str_eq(KID_1, r_jwt_get_header_str_value(jwt, "kid"));
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_1), NULL);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_OK);
  ulfius_clean_response(&resp);
  r_jwt_free(jwt);
  
  r_jwk_free(jwk);
  r_jwks_free(jwks_pub);
  ulfius_clean_request(&req);
  o_free(access_token);
  o_free(bearer);
}
END_TEST

START_TEST(test_oidc_jwks_client_cred_valid_no_sign_kid)
{
  struct _u_response resp;
  struct _u_request req;
  json_t * j_resp = NULL;
  jwt_t * jwt;
  jwks_t * jwks_pub;
  jwk_t * jwk;

  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks_pub, SERVER_URI "/" PLUGIN_NAME "/jwks", 0), RHN_OK);
  
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  
  req.http_url = o_strdup(SERVER_URI "/" PLUGIN_NAME "/token/");
  req.http_verb = o_strdup("POST");
  u_map_put(req.map_post_body, "grant_type", "client_credentials");
  u_map_put(req.map_post_body, "scope", CLIENT_SCOPE);
  req.auth_basic_user = o_strdup(CLIENT_ID);
  req.auth_basic_password = o_strdup(CLIENT_SECRET);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_resp = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_ptr_ne(json_object_get(j_resp, "access_token"), NULL);
  ck_assert_int_eq(r_jwt_init(&jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(jwt, json_string_value(json_object_get(j_resp, "access_token")), 0), RHN_OK);
  ck_assert_str_eq(KID_1, r_jwt_get_header_str_value(jwt, "kid"));
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_1), NULL);
  ck_assert_int_eq(r_jwt_add_sign_keys(jwt, NULL, jwk), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(jwt, NULL, 0), RHN_OK);
  json_decref(j_resp);
  r_jwk_free(jwk);
  r_jwt_free(jwt);
  r_jwks_free(jwks_pub);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
}
END_TEST

START_TEST(test_oidc_jwks_request_token_jwt_nested_rsa_kid_1_ok)
{
  jwt_t * jwt_request = NULL;
  char * request;
  r_jwt_init(&jwt_request);
  int rnd;
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  char jti[12] = {0};
  struct _u_map body;
  jwks_t * jwks_pub;
  jwk_t * jwk;
  snprintf(jti, 11, "jti_%06d", rnd);
  
  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks_pub, SERVER_URI "/" PLUGIN_NAME "/jwks", 0), RHN_OK);
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_1), NULL);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt_request, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt_request, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_pem_der(jwt_request, R_FORMAT_PEM, (const unsigned char *)privkey_1_pem, sizeof(privkey_1_pem), NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt_request, NULL, jwk), RHN_OK);
  r_jwt_set_claim_str_value(jwt_request, "iss", CLIENT_ID);
  r_jwt_set_claim_str_value(jwt_request, "sub", CLIENT_ID);
  r_jwt_set_claim_str_value(jwt_request, "aud", SERVER_URI "/" PLUGIN_NAME "/token");
  r_jwt_set_claim_str_value(jwt_request, "jti", jti);
  r_jwt_set_claim_int_value(jwt_request, "exp", time(NULL)+(CLIENT_AUTH_TOKEN_MAX_AGE/2));
  r_jwt_set_claim_int_value(jwt_request, "iat", time(NULL));
  request = r_jwt_serialize_nested(jwt_request, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", CLIENT_SCOPE);
  u_map_put(&body, "client_assertion", request);
  u_map_put(&body, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/" PLUGIN_NAME "/token", NULL, NULL, NULL, &body, 200, NULL, "access_token", NULL), 1);
  
  r_jwk_free(jwk);
  r_jwks_free(jwks_pub);
  u_map_clean(&body);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_jwks_request_token_jwt_nested_rsa_kid_2_ok)
{
  jwt_t * jwt_request = NULL;
  char * request;
  r_jwt_init(&jwt_request);
  int rnd;
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  char jti[12] = {0};
  struct _u_map body;
  jwks_t * jwks_pub;
  jwk_t * jwk;
  snprintf(jti, 11, "jti_%06d", rnd);
  
  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks_pub, SERVER_URI "/" PLUGIN_NAME "/jwks", 0), RHN_OK);
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_2), NULL);
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt_request, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt_request, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_pem_der(jwt_request, R_FORMAT_PEM, (const unsigned char *)privkey_1_pem, sizeof(privkey_1_pem), NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt_request, NULL, jwk), RHN_OK);
  r_jwt_set_claim_str_value(jwt_request, "iss", CLIENT_ID);
  r_jwt_set_claim_str_value(jwt_request, "sub", CLIENT_ID);
  r_jwt_set_claim_str_value(jwt_request, "aud", SERVER_URI "/" PLUGIN_NAME "/token");
  r_jwt_set_claim_str_value(jwt_request, "jti", jti);
  r_jwt_set_claim_int_value(jwt_request, "exp", time(NULL)+(CLIENT_AUTH_TOKEN_MAX_AGE/2));
  r_jwt_set_claim_int_value(jwt_request, "iat", time(NULL));
  request = r_jwt_serialize_nested(jwt_request, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", CLIENT_SCOPE);
  u_map_put(&body, "client_assertion", request);
  u_map_put(&body, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/" PLUGIN_NAME "/token", NULL, NULL, NULL, &body, 200, NULL, "access_token", NULL), 1);
  
  r_jwk_free(jwk);
  r_jwks_free(jwks_pub);
  u_map_clean(&body);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_jwks_request_token_jwt_nested_rsa_no_kid_ok)
{
  jwt_t * jwt_request = NULL;
  char * request;
  r_jwt_init(&jwt_request);
  int rnd;
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  char jti[12] = {0};
  struct _u_map body;
  jwks_t * jwks_pub;
  jwk_t * jwk;
  snprintf(jti, 11, "jti_%06d", rnd);
  
  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks_pub, SERVER_URI "/" PLUGIN_NAME "/jwks", 0), RHN_OK);
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_1), NULL);
  r_jwk_delete_property_str(jwk, "kid");
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt_request, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt_request, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_pem_der(jwt_request, R_FORMAT_PEM, (const unsigned char *)privkey_1_pem, sizeof(privkey_1_pem), NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt_request, NULL, jwk), RHN_OK);
  r_jwt_set_claim_str_value(jwt_request, "iss", CLIENT_ID);
  r_jwt_set_claim_str_value(jwt_request, "sub", CLIENT_ID);
  r_jwt_set_claim_str_value(jwt_request, "aud", SERVER_URI "/" PLUGIN_NAME "/token");
  r_jwt_set_claim_str_value(jwt_request, "jti", jti);
  r_jwt_set_claim_int_value(jwt_request, "exp", time(NULL)+(CLIENT_AUTH_TOKEN_MAX_AGE/2));
  r_jwt_set_claim_int_value(jwt_request, "iat", time(NULL));
  request = r_jwt_serialize_nested(jwt_request, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", CLIENT_SCOPE);
  u_map_put(&body, "client_assertion", request);
  u_map_put(&body, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/" PLUGIN_NAME "/token", NULL, NULL, NULL, &body, 200, NULL, "access_token", NULL), 1);
  
  r_jwk_free(jwk);
  r_jwks_free(jwks_pub);
  u_map_clean(&body);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

START_TEST(test_oidc_jwks_request_token_jwt_nested_rsa_no_kid_invalid)
{
  jwt_t * jwt_request = NULL;
  char * request;
  r_jwt_init(&jwt_request);
  int rnd;
  gnutls_rnd(GNUTLS_RND_NONCE, &rnd, sizeof(int));
  char jti[12] = {0};
  struct _u_map body;
  jwks_t * jwks_pub;
  jwk_t * jwk;
  snprintf(jti, 11, "jti_%06d", rnd);
  
  ck_assert_int_eq(r_jwks_init(&jwks_pub), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_uri(jwks_pub, SERVER_URI "/" PLUGIN_NAME "/jwks", 0), RHN_OK);
  ck_assert_ptr_ne(jwk = r_jwks_get_by_kid(jwks_pub, KID_2), NULL);
  r_jwk_delete_property_str(jwk, "kid");
  
  ck_assert_ptr_ne(jwt_request, NULL);
  ck_assert_int_eq(r_jwt_set_sign_alg(jwt_request, R_JWA_ALG_RS256), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc_alg(jwt_request, R_JWA_ALG_RSA1_5), RHN_OK);
  ck_assert_int_eq(r_jwt_set_enc(jwt_request, R_JWA_ENC_A128CBC), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_keys_pem_der(jwt_request, R_FORMAT_PEM, (const unsigned char *)privkey_1_pem, sizeof(privkey_1_pem), NULL, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_add_enc_keys(jwt_request, NULL, jwk), RHN_OK);
  r_jwt_set_claim_str_value(jwt_request, "iss", CLIENT_ID);
  r_jwt_set_claim_str_value(jwt_request, "sub", CLIENT_ID);
  r_jwt_set_claim_str_value(jwt_request, "aud", SERVER_URI "/" PLUGIN_NAME "/token");
  r_jwt_set_claim_str_value(jwt_request, "jti", jti);
  r_jwt_set_claim_int_value(jwt_request, "exp", time(NULL)+(CLIENT_AUTH_TOKEN_MAX_AGE/2));
  r_jwt_set_claim_int_value(jwt_request, "iat", time(NULL));
  request = r_jwt_serialize_nested(jwt_request, R_JWT_TYPE_NESTED_SIGN_THEN_ENCRYPT, NULL, 0, NULL, 0);
  ck_assert_ptr_ne(request, NULL);
  
  u_map_init(&body);
  u_map_put(&body, "grant_type", "client_credentials");
  u_map_put(&body, "scope", CLIENT_SCOPE);
  u_map_put(&body, "client_assertion", request);
  u_map_put(&body, "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
  ck_assert_int_eq(run_simple_test(&user_req, "POST", SERVER_URI "/" PLUGIN_NAME "/token", NULL, NULL, NULL, &body, 403, NULL, NULL, NULL), 1);
  
  r_jwk_free(jwk);
  r_jwks_free(jwks_pub);
  u_map_clean(&body);
  o_free(request);
  r_jwt_free(jwt_request);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc jwks");
  tc_core = tcase_create("test_oidc_jwks");
  tcase_add_test(tc_core, test_oidc_jwks_add_module_alg_missing);
  tcase_add_test(tc_core, test_oidc_jwks_delete_module);
  tcase_add_test(tc_core, test_oidc_jwks_add_module_alg_invalid);
  tcase_add_test(tc_core, test_oidc_jwks_delete_module);
  tcase_add_test(tc_core, test_oidc_jwks_add_module_kid_missing);
  tcase_add_test(tc_core, test_oidc_jwks_delete_module);
  tcase_add_test(tc_core, test_oidc_jwks_add_module_kid_invalid);
  tcase_add_test(tc_core, test_oidc_jwks_delete_module);
  tcase_add_test(tc_core, test_oidc_jwks_add_module_uri_invalid);
  tcase_add_test(tc_core, test_oidc_jwks_delete_module);
  tcase_add_test(tc_core, test_oidc_jwks_add_module_uri_invalid_json);
  tcase_add_test(tc_core, test_oidc_jwks_delete_module);
  tcase_add_test(tc_core, test_oidc_jwks_add_module_ok);
  tcase_add_test(tc_core, test_oidc_jwks_discovery_valid);
  tcase_add_test(tc_core, test_oidc_jwks_add_client_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_implicit_id_token_valid_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_userinfo_jwt_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_client_cred_valid_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_kid_1_ok);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_kid_2_ok);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_no_kid_ok);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_no_kid_invalid);
  tcase_add_test(tc_core, test_oidc_jwks_delete_client);
  tcase_add_test(tc_core, test_oidc_jwks_add_client_no_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_implicit_id_token_valid_no_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_userinfo_jwt_no_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_client_cred_valid_no_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_kid_1_ok);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_kid_2_ok);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_no_kid_ok);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_no_kid_invalid);
  tcase_add_test(tc_core, test_oidc_jwks_delete_client);
  tcase_add_test(tc_core, test_oidc_jwks_add_client_invalid_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_implicit_id_token_valid_sign_kid_invalid);
  tcase_add_test(tc_core, test_oidc_jwks_client_cred_valid_sign_kid_invalid);
  tcase_add_test(tc_core, test_oidc_jwks_delete_client);
  tcase_add_test(tc_core, test_oidc_jwks_delete_module);
  tcase_add_test(tc_core, test_oidc_jwks_add_module_uri_valid);
  tcase_add_test(tc_core, test_oidc_jwks_discovery_valid);
  tcase_add_test(tc_core, test_oidc_jwks_add_client_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_implicit_id_token_valid_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_userinfo_jwt_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_client_cred_valid_sign_kid);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_kid_1_ok);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_kid_2_ok);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_no_kid_ok);
  tcase_add_test(tc_core, test_oidc_jwks_request_token_jwt_nested_rsa_no_kid_invalid);
  tcase_add_test(tc_core, test_oidc_jwks_delete_client);
  tcase_add_test(tc_core, test_oidc_jwks_delete_module);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req, scope_req, register_req;
  struct _u_response auth_resp, scope_resp;
  json_t * j_body, * j_register;
  int res, do_test = 0, i;
  char * url;
  
  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");
  
  ulfius_init_request(&auth_req);
  ulfius_init_request(&admin_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      y_log_message(Y_LOG_LEVEL_INFO, "user %s authenticated", ADMIN_USERNAME);
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    do_test = 1;
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication admin");
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_request(&user_req);
  ulfius_init_request(&scope_req);
  ulfius_init_request(&register_req);
  ulfius_init_response(&scope_resp);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", USERNAME, "password", PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    for (i=0; i<auth_resp.nb_cookies; i++) {
      char * cookie = msprintf("%s=%s", auth_resp.map_cookie[i].key, auth_resp.map_cookie[i].value);
      u_map_put(user_req.map_header, "Cookie", cookie);
      u_map_put(auth_req.map_header, "Cookie", cookie);
      u_map_put(scope_req.map_header, "Cookie", cookie);
      u_map_put(register_req.map_header, "Cookie", cookie);
      o_free(cookie);
    }
    ulfius_clean_response(&auth_resp);
    ulfius_init_response(&auth_resp);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_true());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_true());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_true());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);

    scope_req.http_verb = strdup("PUT");
    scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
    j_body = json_pack("{ss}", "scope", SCOPE_LIST);
    ulfius_set_json_body_request(&scope_req, j_body);
    json_decref(j_body);
    if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
    } else {
      o_free(scope_req.http_url);
      scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT_PUBLIC);
      j_body = json_pack("{ss}", "scope", SCOPE_LIST);
      ulfius_set_json_body_request(&scope_req, j_body);
      json_decref(j_body);
      if (ulfius_send_http_request(&scope_req, &scope_resp) != U_OK) {
        y_log_message(Y_LOG_LEVEL_DEBUG, "Grant scope '%s' for %s error", CLIENT_PUBLIC, SCOPE_LIST);
      } else {
        do_test = 1;
      }
    }

    ulfius_clean_response(&scope_resp);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error auth password");
  }
  ulfius_clean_response(&auth_resp);

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_95", "value", "register", json_false());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_88", "value", "register", json_false());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
    
    j_register = json_pack("{sssssss{so}}", "username", USERNAME, "scheme_type", "mock", "scheme_name", "mock_scheme_42", "value", "register", json_false());
    run_simple_test(&register_req, "POST", SERVER_URI "/profile/scheme/register/", NULL, NULL, j_register, NULL, 200, NULL, NULL, NULL);
    json_decref(j_register);
  }
  
  j_body = json_pack("{ss}", "scope", "");
  ulfius_set_json_body_request(&scope_req, j_body);
  if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
  }
  o_free(scope_req.http_url);
  scope_req.http_url = msprintf("%s/auth/grant/%s", SERVER_URI, CLIENT);
  if (ulfius_send_http_request(&scope_req, NULL) != U_OK) {
    y_log_message(Y_LOG_LEVEL_DEBUG, "Remove grant scope '%s' for %s error", CLIENT, SCOPE_LIST);
  }
  json_decref(j_body);
  
  url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&admin_req);
  ulfius_clean_request(&scope_req);
  ulfius_clean_request(&register_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
