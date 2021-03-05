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
#define NONCE_TEST "nonce5678"
#define STATE_TEST "abcxyz"

#define PLUGIN_MODULE "oidc"
#define PLUGIN_NAME "oidc_keys"
#define PLUGIN_DISPLAY_NAME "oidc with multiple keys for signature"
#define PLUGIN_ISS "https://glewlwyd.tld"
#define PLUGIN_CODE_DURATION 600
#define PLUGIN_REFRESH_TOKEN_DURATION 1209600
#define PLUGIN_ACCESS_TOKEN_DURATION 3600

#define CLIENT_ID "client_keys"
#define CLIENT_NAME "client for multiple keys"
#define CLIENT_SECRET "very-secret"
#define CLIENT_REDIRECT "https://client.glewlwyd.tld"
#define RESOURCE "https://resource.tld/"
#define RESPONSE_TYPE "id_token token"

struct _u_request admin_req;
struct _u_request user_req;

const char hmac_keys_list[] = "{\
  \"keys\": [\
    {\
      \"kty\": \"oct\",\
      \"k\": \"R72SkNI08mVXlNSOKCeRxw\",\
      \"alg\": \"HS256\",\
      \"kid\": \"HS256\"\
    },\
    {\
      \"kty\": \"oct\",\
      \"k\": \"K4fSC0yj046M_UOzVm8xQmEyWp8Uinn-\",\
      \"alg\": \"HS384\",\
      \"kid\": \"HS384\"\
    },\
    {\
      \"kty\": \"oct\",\
      \"k\": \"doVfGuP6lRn0-aAX0X9kc5LT7nVdOPvMT6PR4gbGa0U\",\
      \"alg\": \"HS512\",\
      \"kid\": \"HS512\"\
    }\
  ]\
}";

const char keys_list[] = "{\
  \"keys\": [\
    {\
      \"kty\": \"oct\",\
      \"k\": \"R72SkNI08mVXlNSOKCeRxw\",\
      \"alg\": \"HS256\",\
      \"kid\": \"HS256\"\
    },\
    {\
      \"kty\": \"oct\",\
      \"k\": \"K4fSC0yj046M_UOzVm8xQmEyWp8Uinn-\",\
      \"alg\": \"HS384\",\
      \"kid\": \"HS384\"\
    },\
    {\
      \"kty\": \"oct\",\
      \"k\": \"doVfGuP6lRn0-aAX0X9kc5LT7nVdOPvMT6PR4gbGa0U\",\
      \"alg\": \"HS512\",\
      \"kid\": \"HS512\"\
    },\
    {\
      \"kty\": \"RSA\",\
      \"n\": \"AKdOqHA5Vvcsgwv1Ag7MWzIuI6Snm4aOaccLcMQOUxXrLyVC7F_yi2BaCK_rJaBKKUo0ybu_KQhtBhlU7k-7izcbYW3K0lfZv5Zk-01BXHUhlniATXoxOp1UaJPD_Wkwqjgdgnwch9Nt56Wh742qlXyeoj8ywlApW-80yv1UperZXDQ0sCnp1ztbGX-D2B8MPyhJlTKPWB8_LJJ_8VveqwS8Cs8xLD3OUd3EZCdqGlgDmjvwg5PWnULATiu1DiOR4nUXLDP0nCa7-s3NqSKhHENcCDNpCFmWCtaMltvOTkh6hdOoZJ9Lq5ZrjL-7UuCwgx3VlcwubByER1s04Ir8-gk\",\
      \"e\": \"AQAB\",\
      \"d\": \"O2z26xWSzCylR2P5HSR85-_3fQ6DcWG4NJjdruWfoVNt5YBF0TanRsvz9fhB3xM4Y0EovmUBwBppZioCk5N7uVEiZAr8d3PCVzr6_8_NdVU-ywJXgqVlumg21PVyVyCP9WqV5FuF6xVIiE5idiE3A5Kc8nGnDy4Bl49a4mxkmmuTClCRZREYGGJp-zsQCH65VhMfnzAeIEQ0FPZ_b1SkUwlU_PJ5QVXtbkueOu8FJJpwrAVLoYYZE9ccxUeHuCEsW5l1NL3snyqUw1oR299hjBenSFddrdfkjGzKshumhREMnGaNRdYC2oAenOL1LPWM-flL0qgEnvqLkDj2J3FcAQ\",\
      \"p\": \"ANG8kXHtC539U-KkdVIT1qGvsR-s8Yg1kGnVPsGBgBhf02rzcg4steMb8NcqVfbPPOjz-8luhVhY0Eij6Q3ok3CefebdtdcvqN-8bXzmEglHCiw0MkcVYw_pIfReB9relyloyKodnSvnsFKTZ8lU-02H9sZ_kmuLU7C0O70jptpB\",\
      \"q\": \"AMw2L0-CA9gj2Tf7OVWBckHaYV1pdzfsS-OnKk7Hppw8z1-3xMSX2Iz50GvyLWkFS2V7LsabobLHlEuwtE0g9sj5WlWRKEwoEPkWGG8JOxqDgoqMqB32TCkA467XtYH9Ch6pWVezYFIlsRNGX4YdjH9LxCHNlwRtZB3pxCuPMl3J\",\
      \"qi\": \"AJ8ltjqbm9h-i5CMT5FQcUwdUkV-m45dicmMLn2dV3_R6z-CeYTjJYnIyEoA6AdZdQAUfZMsbjKO_bgDey_J-KxIvVby0FZpkfl36yrR93lMOv3A2hsTXpqAaqFX20Ph3w9SypqTH9oXD3cAJ7Rlh_5jdsX1kXzoeQ_VPgEFH-CX\",\
      \"dp\": \"Y-S6KVbLh64WfAX0Uulb-pphdEK8rzFD3QRR5Xw2dGV_nprgodutrcOrC_AADZNa4WEDdUcMf62dVlurLpKtVqBGOuUyLJFoj1eBllFGGeEZ-T_LCownKHbTUz5N43LM8E4V9OAx8a1iD5JhhkTRhHXTlWtBY7NyYuEU6trGJ4E\",\
      \"dq\": \"BC9MEuYILCK37dTBHQZ1D_JosmBZ6BR4jaa8UDb5LBR273A1oQ23i1QHOF8THSbVn7PBhqJj0uUSHeb2GuqFBCNP_Zbm64CasHAKeiQHSQjO4QX23_5PGzwAbnHPL2W_ElfIE-sCG0zYbxuvE3GBko4767Fp2dZgCdjjgz0A_Dk\",\
      \"kid\": \"RS256\",\
      \"alg\": \"RS256\"\
    },\
    {\
      \"kty\": \"RSA\",\
      \"n\": \"ALnTB6D8SIi9rFFbbEQfqPR2_b95Z3T0_ZKxkPh7s1uENSb7IN5bW-30lSsjifMKgiETbAepKy_JF9nZVQkoweierFOaLRNiZn3WAO3h2NnO9YXt25P7P5BF1klItIXxi7orEIIdYJhL-v6p3FGsv45jYUw9g0t-HcRBVdWrVw7rnAOJn4N_RTdEPjm9VotBsmf4P-1PfbTazJ1SirPlbJ9q5WgrUhx1z_aVQNDKl5kJGYBtldnNiV9Ql3YjW9jO30NnVEXqYj675Oc3gasG0jtWG8jQTV24SBImfMoYMxlzJioXcFYPp1AWtVzYbcDTgZYr0WFrWuBgsQ5cWHEL9BU\",\
      \"e\": \"AQAB\",\
      \"d\": \"PQptPxygVwq3SCJX9ijQPz23LOacbXbstPtPO9CmojFTpHJp4aDxGcF2Hq2V6xhQlrzih8GyRggwpYcWv-N7jwZQZUYH-I4iTMO3mmzN5v5s-Imhz4KA5suKEJipdDZcR9NNoPA1gtGyqWTy0oGEiylqFLlAH9RVwtoTcBTQjD2YvZXZ6nzG4ALNeqyynn0-PA7rfPRCo0CPL6oHxtTK4hR_0BmxV43eKLsPzlkbiSQlcI7paMLAMrzN-rhEjE4QrTdXpB0MGHzfaTJqoRCnL56N-oHiAJGhDnMVep5-VjNLw_TMg7_LQz5X4F4uS6u2392OTsErmylDPwtiZk_fAQ\",\
      \"p\": \"APWISggwJKw80geRUN2BuLQLOOWwPIF-7GunMwb341srz5puNX3VqR5FMlPoM562j_jWe3jndgl6auDIYQKaae4ImPJ80-z_kaNASGPhz-GZC0rPUULEUFWbxVIgXAgvVnQuScc3QS41AxdPuZnCXdxbZFoz0jYZBj2JqWlwUeOZ\",\
      \"q\": \"AMG_GB4HQ483yUn_61DaiqZZi_yVK1gEzhmcHSSXnQSG7P0akpbm0iTRt33HF6nNpJ6oXzS7yB_XO-UDfm7hIkpsp7NeGovSg00XQ1uUkU_z8TsIuBEiWlLs3Vy6z8DhuJfUyuVtbe0JE92dXQ9t7iW108JgT0sQvL3QD0oeeeHd\",\
      \"qi\": \"X9_Sao4DCwdTBD4LVRI5Zb14Mf9JNiGO_swzVDUsZG79eakYQg1GzRHhx3sG_CsPXMsW-_EOLYEOVvNIc1DKPIExR1Owifp2Tj00Q2BtEj1t6i_5cUexXf5KuacIhnF1O2zrAhSiXXAlEHaA5-hDGIvITtXIY3j2vMGcudzonkU\",\
      \"dp\": \"XHGzBgAyXpMLtQO2gZ_MziUHiBthvJPwKdwq7y238WS-ZnOmOjmO0jHVcBgWD2THMjZ3CJ-FJq5rvTRUqik_Rvr_sxTiqfHTgLa8SrcDkPoRcVo7Szsk0Aa1NWWvoPlJwLaI2rPoG6CkCEvhIo42zreuQfQO6oVjfxnsqiE7A8k\",\
      \"dq\": \"CDHg_0QnY2NkrDCa72yO-MJI3YIhtzNc1FB6GxYemhZq57m8AY35zXzhWfyVz6TXFa7heAWJTW95JRKkwmPbY3J9FWUhklBxJU2al8EM9GjJB0ozHuZpE6DZLBbquqnRePqTKmkagTAlGvaQ_RoVPJsYPdx8_hvTH-QxAV2QojE\",\
      \"kid\": \"RS384\",\
      \"alg\": \"RS384\"\
    },\
    {\
      \"kty\": \"RSA\",\
      \"n\": \"ANI6-B_hZMpUPoQTLHY5GjqJ1ry0138PgWy8JWfFkKwIKpkFZ_ps9rNLeZf1bztLcSruB4JwZZPk4G-wzB3Adz1Fk4nNjvBnRNiOIgEUlhCMCGPyPuz9Dbxexz8l5Cc6GZOxiMmxcOFM-tbQSlY5oVO0M_vSgiDJblyxyNvOxNDoV1hIRB6NfDKPkQR_6gNHqIKV1LIQ2-9PJn6RI5eR1u7z5no7Vj4ygBKG_hWyA4Mg-yiYNgdgycdboGlx6DJivjHT10NMtQYp2eMjnCmtrGYobtaHmTnyCWoX5V5St9CY_pdl8ymMq9fq7kn0ILd4b9CJEcgjV6WZml49mKf1-vU\",\
      \"e\": \"AQAB\",\
      \"d\": \"AMkCBRhGZB5oqlWSF6L6Oi_ad21648jjRHZ49rLf3dH_BOvGlYKGCOOpuJso2q-xFIVdjeSUHytnXYitXJzd16TID6dk2dTWiKceTzkFO-6aVbNqfewOkMGZRZ0FV76B-M6UoxtmA24IMpaOFWWYOL5VwJZ40l8S-ei7PDee3eR3ZjrluZEFV0-mLWJ5ndyp4Xc2hT7w0I4V_YgehIkSY52ZDLZD2Ne8fDd4KBFbGXvyD7N1Ipb27N2gRZNJcZfnXOEEWf6lRT52-EhmjQRlVwnIE9phLr5CzJfHIaVbQXXpIjBDezQhHF-Bmz15vWOR6_bk22OwN8tAAD4cNKPUvkE\",\
      \"p\": \"APSgxnyWMhFQhaIhKQ3j4G0YpSUyL1VWyi4Lhl9SArU8AUsw1F7RJCdLqtV51iaRfmmewUH2oA2g3gFWXElvZ5xCWHohn7g2OOhlq4CPt_McLRj7zfkT91l8Bkn4LFkpDua6XVYPehs-H-0IBfAS7u2PEc-UYVQUh18s6OFS8ZaJ\",\
      \"q\": \"ANwA1xr8goFfiVpXAFiHy3JZlyXW-TcMlW2YEFg9IZc-l6wYzty1iLJlATT_bo79b4CYGCXuem8UtusfR4HyIYH5SCczNpvwqhloOtQ7zEBCGb2QlC6qhR847DxtdYZ7gSM5K08lSBcABKnRMZAlZuhD3V5CMGuRK4vnU3JUUSYN\",\
      \"qi\": \"AJ0vFeqZz4OsqpyyHnjIlqVONX0qDgL797gZuPejlLCD2Ur7SA33gKLgLGBUB6xyAyfW_e0I9uGa8MuOGqE3r7NGItajCH3GXyjDz7GrkbQxogmyVE1mLkHnuNKpHcbH8ImVmRYI4RjKoZGpdVUN8YDoYueWjX-dm12asOttpOrM\",\
      \"dp\": \"AOy6zXnxa0BAOSHdjzom5J8Os3ocZ5vhIkSO2JlT5tT13ZajCVE8eQ0h948gmXG3aKrTe9fWz6qAm3aV2TcjfRPFTJPcCBGfP1D-WopOCkhUYvwDaZ75iGtrTzaz2E7sIcR8YyiOT68fXovmMMDTwa3Yvvavc8SHHT2oWzD6MFpp\",\
      \"dq\": \"AmMD8mgA5nRp4hAFkfBPNbthF2kApSc-y8SVkM-A-MoWDSjrvZs-k2jjHXcT9Pss5YFA6dBvhZr87QoW1YMR9_4DWWGF2yU-Qy5NTRYk_iF5dAQIh4UUEqWkcndhigb2_LHXFXG7GXzHkCwT1JODTUvHMAmZyuD1TvxAfIILq1U\",\
      \"kid\": \"RS512\",\
      \"alg\": \"RS512\"\
    },\
    {\
      \"kty\": \"EC\",\
      \"x\": \"N1o9dzRYW_LYhT_gDKJGabUCcrClQuP6P9CpHrd7BuE\",\
      \"y\": \"AOmhhdwGbLQ20Zrftyjawal1LmG9Ai2Fgh_SpBqKJZli\",\
      \"d\": \"Az3F0-LiPboaKUt66OW8sj1BK4EGGkFl3rUX08h2G9A\",\
      \"crv\": \"P-256\",\
      \"kid\": \"ES256\",\
      \"alg\": \"ES256\"\
    },\
    {\
      \"kty\": \"EC\",\
      \"x\": \"AORgXiOIgXRKHnyHozRKHy9QOUq-m3auoyEUAPmQ7Rv7yX7juRO5bKWFEFTNuwYxEQ\",\
      \"y\": \"dCURk3PMy-vL0_-5yCcM6HyWdpK16ptzIFwL0a1DW8UpMSF9hrU9uy_8LD3tstMM\",\
      \"d\": \"XGDl5tRyBSJ4gzMb_uK0AvuH9Oayts4vreKmZ3yYl17yQeKE5l42Noa7ZuVZEDCU\",\
      \"crv\": \"P-384\",\
      \"kid\": \"ES384\",\
      \"alg\": \"ES384\"\
    },\
    {\
      \"kty\": \"EC\",\
      \"x\": \"AeRnJbSK8mHeovK7BwrxJ-974Euz1JJmU58BZZiHDJjp7SW4G_ZrZlmSk7_iQn44YFvNST26LefiPJdds7wLPsne\",\
      \"y\": \"AT1ifPyZZeixmCyLUSGXgq7QIRYBXj5pGFbS90PMHJkzfyYqPX607AhVbuqVaIpZb4zFUgkSLPaU08JihEhACABx\",\
      \"d\": \"AQ2CBfGYbElfZH4W0-LUJaiRvI_MdHUFDJGtY4Ns693GwqTjkZZ6Aq9a6htganWMuFE-jVZidkeVW62kctNfw7UP\",\
      \"crv\": \"P-521\",\
      \"kid\": \"ES512\",\
      \"alg\": \"ES512\"\
    },\
    {\
      \"kty\": \"RSA\",\
      \"n\": \"AKArSp5VLTNyDMGZnDNeoBmtHB8JBgJAYe45l5boakDsVBAN1Qx8qQbk1lcLJpSr5yYG4f3EmoxKloDGlLk6WDrcitqUIUfwM5lFdl5Vs1MbGffV3nFSbnWi1vW_cJh1KCwMa6S3GAK5w3j0roDDacJ0RxRs9x8MBHCLvT4cuylm2YVn22pfad-LROwO847x8KEFy8jluiArHVfdQv7nSeulr6r-JO9SrUmyeHWKSli1ZXjf6ZlArn63g_bn7WXTCagefP01H3vcSgTTZ4BTcnHcvNSKcwdYZDqyZII_cwJyg206VQzvl1UjgmMqfFzV1iCdyVKbYnuDLF4EFu0jgeU\",\
      \"e\": \"AQAB\",\
      \"d\": \"AIiCXSZ1EgE2wwh-E1L04x7_G2iYGDbzCIQxMbG8hFKxGTRVla7-0FC_2K53InqzyF3wn8vZNJ89MuiuVzNHNst0DCQe-_6ECnYnbasY_61k-8zuypdq2hoIn4zzjNNjhsmEDHpmUmCAUslUQSYdZpYE5E_UTwp3A5Goh7HYauvtE2tRgfdMusOQlQYyX-CMyJ4TTDDv5j6opo06BWPAXnLP42LdQLLA-nsF-qhIWgju2t_gKQgfvOtCihO3AqMs6Lj1APiBjKuluREcfYRiGr31sMPpegJn45NJBSBz4ge7sAQmrNZ0bEs10RLfAmIlyXv-wneW3wFhjAgRhV7gYgE\",\
      \"p\": \"AMlru8fpK4zsRmMvreD-P_pq1a55LNL8zVMd3-aiDatpu_CsoJMxa7GohRSx904eE3zdgTe-AsC4jtgFxQU5E7QQbGc9wUCd186YFfHy8PdHvwDUv4ljaPkdq8XlJaGo-ui7NhKTUE8OFkfACP2AcN0HY3LSl2CjSiJZq08e9lgd\",\
      \"q\": \"AMuR_IiAVB6UnpmeuCmT7-KCUx6vcA1G7-pkX2SWBa5n41Z71SgSOclqeE7yIDYCIGNL0_v03iKFs_oVpoH6OWBrMaLZU7pJqDWnvxQqBbiK6WGvJ4ouhd349l_x-jNXIY0OdPctR0WjqNr5JfHW22xeDF27E_aWS5qVHT9CrHZp\",\
      \"qi\": \"V8Eyw2hRWqBtuZIS6O4b3j_oc9M5SeX_cyKWFok3QpZNv5OXtBVR9SmZDh-oPPOs--d3Pj7cn9EjyB8ji3NLjRNc1bHlqaUHFPdmViqxWw2OPgBWKHvRmpjWCbmcn9BZ9PHFlRsyNJCqNDgrvlda6gvvtL_SnPy6MsAmj2Zn4JQ\",\
      \"dp\": \"AJB5Vhfuh-5tC4_Zgz7_H6TfPKYJBL3R1vTnWNJ1KpjpHoVjTUpHCJhF6C8P9_NwX0oRF76D7DWQK-WHPeqhJiDiJt9mzFcs4L6vGA6T04OLUtWlxD0nsQP-5FbuJi_upQqKPh7Uy6Xo1NJiTBCJMGtaAVs68pm-hk5dQyNdchWB\",\
      \"dq\": \"F8MouT5Rk2hBwyjV0nSkUcporXJJICOhqbihsfoZG6ygyt2VmiHWgP5eoMh-ng9NfInDauvAakM1KQIR96YfwHOCzcGUlnA2pFy6Xz4wgMQmTfLGKMkZczm2eKikTg3jqrV_TcMJSMW71iOzHDG6V0H7K43E3MnadWbmjRXZT9E\",\
      \"kid\": \"PS256\",\
      \"alg\": \"PS256\"\
    },\
    {\
      \"kty\": \"RSA\",\
      \"n\": \"AMEdUKWQiNUSkVQDbe2D6FxTG7wlLvzqA7W-UcZXJeumPH4CXngg2cOj1gXLG_D9qODjYjcYduc0HZghxx-ievk1JLyYZsiUwml1xXHmzOHU1VTdQO9RrVO1ZitcR1vRB0ZI0oCBIVqubcNQjhh_k6TNjLZyaToF1AufZyKYVp4LC1-jXp_Ffp74AcMSFroUPJ8FUmv7grqCfL3US7DOfeG2CIaNY6SWY13PdFJ9lh2cMrRWkqgl_1rvIbUvAXc-oAEAYd_x0D3dQvOhE1Txr6WPh-RENGUFAyZmLWH-hyM7KWW1TqTjyPwZob-hAqXmhc7qAWq3GYnvc8QFFr7JNlE\",\
      \"e\": \"AQAB\",\
      \"d\": \"AK9Cwaxg7i4iOc67hgqnSjxwGJ26SVizsUZCQcj10q55IjFiSQZRGhFaIaUEXolqTNg8xSgnhdHzFGC7VxI4zc5aEssurSmhCIfZoKXsx0i1dh8c5g_MWre7y8vSZdjIbge1k4WYrAK2h1tZQnytW_uXqPrz_tfv7i_WLS3Sf9nRrF2xUMFcZNqwzo_Fq-XX4E5htqaRa6DNm6rk7NoYToO0WycSt_T9TYGT1n80vmwQMXx7Uuu7Ty99hJTf66PqwIzhzKg7vzjdh7raN2VGjURhFJPnJKtb3w-rbXlyy63szS1R1MmxfGl5r52nrl6HE_LdS2vFHTdOVSkC_XWC63k\",\
      \"p\": \"ANatNcDP5BjI5ceR6fMPFX6IgXmi-NBrj8Po5jk-Xbeqbx4aQ4Z3-1ZWHb0JhDNXNgvHDPZ5IA5POdLp9Y3awyokr5FFHwFdO02or6dwE8yAYmASzHRiDblzXugymDBmoCLp6KkabcKN_drba6lSEvPFEX5mKlp5ZnrQ-4q8Mwc7\",\
      \"q\": \"AOZJkqFAnhA20gwv6oyEqeP_WadJZK7fbFqsPrTWONpF5g1iKnK3s1dXUIL1s5Mh7Xmsw_GzrMp10Zx_pF0RKA2kdJWCWTpXBLEjyNLx_GR606SiHXke5bd5MAislogKoxYkNNTe9UwZ15hXS3aeznSDMvumG02LzoiUllLkcpfj\",\
      \"qi\": \"AIl5ah-ymgxJqZ6m0QJQdqBy7CHtn_14a8RYdMUCfVv0Bu8CZhX83Jiely8QUYJMH5dNNv1T3EepKX1J_6TTF9KvhOSIb9XmN5c70MP3x6jG2sdKegJ4-a7EvK9rvcBY8AtQGf9kgTLw76stMuAk2xtNcQBHEI7iLGcvi7-3o4PI\",\
      \"dp\": \"AMPmij_qNi873RuyFricEjRGo0h5pO6kySuw865XMDRzjjT9KJOkF7KgoUCpV392XTaALV8aB1unho_muhL6B9EEa0Z4uiOHjZ9_iNOV3itnGN6tKPAnrniGRJxF10WL0SQrKgpuuKyq4HYAd42q_OqA8kbTOmEXmaIH5ROkTDiT\",\
      \"dq\": \"VhfJVrmmnh8wldfQEyqBrThIly7sEih7BMcCRm8UIB4jrHs3rV2aEZwWAG_E68uyUVvSgWkPvz0e2SgrFZQVakxCPabWnuXrXiInsR1Ao3v75b-pzx9K-DW5THThbgi0AdIVYkPcZs_-dvijwLwMKSjnhYcLDAmpdAxAysqXQMs\",\
      \"kid\": \"PS384\",\
      \"alg\": \"PS384\"\
    },\
    {\
      \"kty\": \"RSA\",\
      \"n\": \"ALY15QZjkPepRc0dcPt8pcvmINe9z844ZuuB5O6CHmb2fCpQF0fqn0kOC-ZRuaf13WMO9yZ5KHveH9-2FyeMrOljObYvBRgIiwvlg5bSZ8l7jq4BCX9PoBkcIKIfHqaULh8gy6Go9421cOFimoQ20DR3Q1xAKg77qOeiVzhKDtWZUpsZmNgpq3Y71B5ccHIeuczTu-YbjSGE-xiTnIH8RU2198pm_PIDDoBAGvX6MdLpyluz5fzLImFvEOuHlfpZtjLPVD4hfsJ7J1fw_pnKfUsKD_AlCJLC7E6xpCQM616rGC3aCaUwCGaFiNTCaSHPvmSBQ6FAGAWc8iy5b-3P59U\",\
      \"e\": \"AQAB\",\
      \"d\": \"czYqxVppjJ-kuih2ix3qu72cYK3tWsjBEwLEHad6z8HlCuAviFKrOwc9sPlV-gT1YjBRSCtt1LzDzLGXfHNv1fbew_qBLwwf13rdNJ1_8J9GvXF8btqLMbVeUQR6XfvuGdKjz2lGdn0WjfzKFPWPusz6c7dCoMyxpR06JyZ0sMu5tngizgcosYv4k4eJNhvvNXIYlAMTfr9rvoMb321-1GKs73bhRr7NDQIaC62d0Np2E5u1rnP4Rqn6rJ99ZptodIzKqNJYxMqqdRkdGdMEiLUyheDOjNqyNYvc1O4h9NNKKkJ4CeFHeasAlV8gMREZ3fvYWbJjz5HK7-ECZxWSAQ\",\
      \"p\": \"AMAefKNqGgSlUYMBt1J-GR-Q2WzMgGZICjMXq0koR7NNoGAiqc6dECRfHGu7agDKwOjYT22u37UsGwYLLmlkmGM2qtkVw6998vk763JTYlqE1QL4EQv0oYjNw5rYsV1AhsIdKjf1w1d2uVrqc2bZ6nqpGM9XVIb_vJ-1atFnhx2B\",\
      \"q\": \"APLL-Tcygf9WxVLdAEV5eQznR2OBJbpgGxQgUoM8r6hL7O9C2FPgWXXb7da-OC-0-Xkm6axDtCsST6qitKd6fNyk5H2YF1LwhJoGIV8Pd58KnxDRPIqF2BoBYJT38It2KTw2zLRVJBHHjxRuAf_tCZpAQZmsVVt_xzZtX6S1ORxV\",\
      \"qi\": \"atMm2Yd5Q28B_QhxMxDv7BQbpnjpSyI_UVK2ugj4Y3wLfuFsk4gkDrvrSUVSnbk4BiWAKwHx4PpvIxDfaxaspp0xOJ6Luil-pA4JRU2fQSzDSnjsokpF7jrA0WAlsugyv_DAfMV00qsBAfTNmVVNpTsNE7q9_py1joJnQW7Iibk\",\
      \"dp\": \"H6Llk2NddXZjvdcCgSsSqAgKRchHPJCQXWmAY0Omyvf1eN88ZzGl_tdKrtLl2cuJiM5WBhHN9N-Wc6BTvDc8gNn3uFfFKZjr8e7UDrd8crt8-EgxRm66SvTXSSB11I1To5N56E0oJbb_PuFsr3sjCZ_e3gXbfX-PaB1PwbvynAE\",\
      \"dq\": \"ALPyMNaT_Hz-Fmj_mn_jM7A4iVRaF1g2eltESWMyyw10mDoL1MD1edg8E94gRQw2mN8N1An0c8eoXpsc0798rKXrH91lp4O09tIg0QLfN80L1jBkovYXlL5RXv-JcyIphQ43nyfYIk97E7QUhC7lw0Qrc3MtomWaIk9YaJZuKdGx\",\
      \"kid\": \"PS512\",\
      \"alg\": \"PS512\"\
    },\
    {\
      \"kty\": \"OKP\",\
      \"x\": \"eKLjYeHBciTpBOKvIslSwbhvLa6Ae1PoBx1qc5knCAo\",\
      \"d\": \"huEf2dA6765FzdfPb7N7QXOwJsuqgM8eYtnupFR6Tpg\",\
      \"crv\": \"Ed25519\",\
      \"kid\": \"EdDSA\",\
      \"alg\": \"EdDSA\"\
    },\
    {\
      \"kty\": \"EC\",\
      \"x\": \"YKXJmQ4x8J_6PN49KMKQylUWVhCU5L3IO8q05GQN83g\",\
      \"y\": \"QgLdjSdd5fbkARJTULCxrXqV4VJaAqI5WjwDzSdhbSI\",\
      \"d\": \"YaQLxs-ZLxr1MmwE1h-h6kBnD3_qTKKBhKTJlQVwJWI\",\
      \"crv\": \"secp256k1\",\
      \"kid\": \"ES256K\",\
      \"alg\": \"ES256K\"\
    }\
  ]\
}";

static void add_client(const char * sign_kid) {
  json_t * j_parameters = json_pack("{sssssssos[s]s[sss]ssso}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "client_secret", CLIENT_SECRET,
                                "confidential", json_true(),
                                "redirect_uri", CLIENT_REDIRECT,
                                "authorization_type", "code", "token", "id_token",
                                "sign_kid", sign_kid,
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}

START_TEST(test_oidc_all_algs_add_module_ok)
{
  json_t * j_parameters = json_pack("{sssssssos{sssssssssisisisosososososososo}}",
                                "module", PLUGIN_MODULE,
                                "name", PLUGIN_NAME,
                                "display_name", PLUGIN_DISPLAY_NAME,
                                "enabled", json_true(),
                                "parameters",
                                  "iss", PLUGIN_ISS,
                                  "jwks-private", keys_list,
                                  "default-kid", "RS256",
                                  "client-sign_kid-parameter", "sign_kid",
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
                                  "auth-type-device-enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/mod/plugin/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_no_kid_ok)
{
  json_t * j_parameters = json_pack("{sssssssos[s]s[sss]so}",
                                "client_id", CLIENT_ID,
                                "client_name", CLIENT_NAME,
                                "client_secret", CLIENT_SECRET,
                                "confidential", json_true(),
                                "redirect_uri", CLIENT_REDIRECT,
                                "authorization_type", "code", "token", "id_token",
                                "enabled", json_true());

  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/client/", NULL, NULL, j_parameters, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_parameters);
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_hs256_ok)
{
  add_client("HS256");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_hs384_ok)
{
  add_client("HS384");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_hs512_ok)
{
  add_client("HS512");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_rs256_ok)
{
  add_client("RS256");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_rs384_ok)
{
  add_client("RS384");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_rs512_ok)
{
  add_client("RS512");
}
END_TEST

#if GNUTLS_VERSION_NUMBER >= 0x030600
START_TEST(test_oidc_all_algs_add_client_es256_ok)
{
  add_client("ES256");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_es384_ok)
{
  add_client("ES384");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_es512_ok)
{
  add_client("ES512");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_ps256_ok)
{
  add_client("PS256");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_ps384_ok)
{
  add_client("PS384");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_ps512_ok)
{
  add_client("PS512");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_eddsa_ok)
{
  add_client("EdDSA");
}
END_TEST

START_TEST(test_oidc_all_algs_add_client_es256k_ok)
{
  add_client("ES256K");
}
END_TEST
#endif

START_TEST(test_oidc_all_algs_delete_client)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/client/" CLIENT_ID, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_oidc_all_algs_test_client_ok)
{
  struct _u_request req;
  struct _u_response resp;
  char * id_token, * access_token;
  jwt_t * id_token_jwt, * access_token_jwt;
  jwks_t * jwks_verify;
  json_t * j_jwks;
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/jwks",
                                                      U_OPT_NONE), U_OK);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_ptr_ne(j_jwks = ulfius_get_json_body_response(&resp, NULL), NULL);
  ck_assert_int_eq(r_jwks_init(&jwks_verify), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_json_t(jwks_verify, j_jwks), RHN_OK);
  ck_assert_int_eq(r_jwks_import_from_str(jwks_verify, hmac_keys_list), RHN_OK);
  json_decref(j_jwks);
  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  
  ck_assert_int_eq(ulfius_init_request(&req), U_OK);
  ck_assert_int_eq(ulfius_init_response(&resp), U_OK);
  ck_assert_int_eq(ulfius_copy_request(&req, &user_req), U_OK);
  
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "GET",
                                                      U_OPT_HTTP_URL, SERVER_URI "/" PLUGIN_NAME "/auth",
                                                      U_OPT_URL_PARAMETER, "response_type", RESPONSE_TYPE,
                                                      U_OPT_URL_PARAMETER, "client_id", CLIENT_ID,
                                                      U_OPT_URL_PARAMETER, "redirect_uri", CLIENT_REDIRECT,
                                                      U_OPT_URL_PARAMETER, "nonce", NONCE_TEST,
                                                      U_OPT_URL_PARAMETER, "scope", SCOPE_LIST,
                                                      U_OPT_URL_PARAMETER, "state", STATE_TEST,
                                                      U_OPT_URL_PARAMETER, "g_continue", NULL,
                                                      U_OPT_NONE), U_OK);
  
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 302);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "id_token="), NULL);
  ck_assert_ptr_ne(o_strstr(u_map_get(resp.map_header, "Location"), "access_token="), NULL);
  
  id_token = o_strstr(u_map_get(resp.map_header, "Location"), "id_token=") + o_strlen("id_token=");
  if (o_strchr(id_token, '&') != NULL) {
    *o_strchr(id_token, '&') = '\0';
  }
  ck_assert_int_eq(r_jwt_init(&id_token_jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(id_token_jwt, id_token, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_jwks(id_token_jwt, NULL, jwks_verify), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(id_token_jwt, NULL, 0), RHN_OK);
  
  access_token = o_strstr(u_map_get(resp.map_header, "Location"), "access_token=") + o_strlen("access_token=");
  if (o_strchr(access_token, '&') != NULL) {
    *o_strchr(access_token, '&') = '\0';
  }
  ck_assert_int_eq(r_jwt_init(&access_token_jwt), RHN_OK);
  ck_assert_int_eq(r_jwt_parse(access_token_jwt, access_token, 0), RHN_OK);
  ck_assert_int_eq(r_jwt_add_sign_jwks(access_token_jwt, NULL, jwks_verify), RHN_OK);
  ck_assert_int_eq(r_jwt_verify_signature(access_token_jwt, NULL, 0), RHN_OK);

  ulfius_clean_request(&req);
  ulfius_clean_response(&resp);
  r_jwt_free(id_token_jwt);
  r_jwt_free(access_token_jwt);
  r_jwks_free(jwks_verify);
}
END_TEST

START_TEST(test_oidc_all_algs_delete_module)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/mod/plugin/" PLUGIN_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd oidc all algs");
  tc_core = tcase_create("test_oidc_all_algs");
  tcase_add_test(tc_core, test_oidc_all_algs_add_module_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_no_kid_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_hs256_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_hs384_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_hs512_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_rs256_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_rs384_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_rs512_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
#if GNUTLS_VERSION_NUMBER >= 0x030600
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_es256_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_es384_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_es512_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_ps256_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_ps384_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_ps512_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_eddsa_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
  tcase_add_test(tc_core, test_oidc_all_algs_add_client_es256k_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_test_client_ok);
  tcase_add_test(tc_core, test_oidc_all_algs_delete_client);
#endif
  tcase_add_test(tc_core, test_oidc_all_algs_delete_module);
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
  json_t * j_body;
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
      o_free(cookie);
    }
    ulfius_clean_response(&auth_resp);
    ulfius_init_response(&auth_resp);
    
    y_log_message(Y_LOG_LEVEL_INFO, "User %s authenticated", USERNAME);

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
    
  }
  
  url = msprintf("%s/auth/", SERVER_URI);
  run_simple_test(&user_req, "DELETE", url, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);
  o_free(url);
  
  ulfius_clean_request(&auth_req);
  ulfius_clean_request(&user_req);
  ulfius_clean_request(&admin_req);
  
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
