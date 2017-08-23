require "./lib_crypto"

{% begin %}
  lib LibSSL
    OPENSSL_110 = {{ `command -v pkg-config > /dev/null && pkg-config --atleast-version=1.1.0 libssl || printf %s false`.stringify != "false" }}
    OPENSSL_102 = {{ `command -v pkg-config > /dev/null && pkg-config --atleast-version=1.0.2 libssl || printf %s false`.stringify != "false" }}
  end
{% end %}

@[Link(ldflags: "`command -v pkg-config > /dev/null && pkg-config --libs libssl || printf %s '-lssl -lcrypto'`")]
lib LibSSL
  alias Int = LibC::Int
  alias Char = LibC::Char
  alias Long = LibC::Long
  alias ULong = LibC::ULong

  type SSLMethod = Void*
  type SSLContext = Void*
  type SSL = Void*

  alias VerifyCallback = (Int, LibCrypto::X509_STORE_CTX) -> Int
  alias CertVerifyCallback = (LibCrypto::X509_STORE_CTX, Void*) -> Int

  enum SSLFileType
    PEM  = 1
    ASN1 = 2
  end

  enum SSLError : Int
    NONE             = 0
    SSL              = 1
    WANT_READ        = 2
    WANT_WRITE       = 3
    WANT_X509_LOOKUP = 4
    SYSCALL          = 5
    ZERO_RETURN      = 6
    WANT_CONNECT     = 7
    WANT_ACCEPT      = 8
  end

  @[Flags]
  enum VerifyMode : Int
    NONE                 = 0
    PEER                 = 1
    FAIL_IF_NO_PEER_CERT = 2
    CLIENT_ONCE          = 4
  end

  enum SSLCtrl : Int
    SET_TLSEXT_HOSTNAME = 55
  end

  enum TLSExt : Long
    NAMETYPE_host_name = 0
  end

  # SSL_CTRL_SET_TMP_RSA = 2
  # SSL_CTRL_SET_TMP_DH = 3
  SSL_CTRL_SET_TMP_ECDH = 4

  SSL_CTRL_OPTIONS          = 32
  SSL_CTRL_MODE             = 33
  SSL_CTRL_CLEAR_OPTIONS    = 77
  SSL_CTRL_CLEAR_MODE       = 78
  SSL_CTRL_SET_READ_AHEAD   = 41
  SSL_CTRL_EXTRA_CHAIN_CERT = 14

  enum Options : ULong
    LEGACY_SERVER_CONNECT       = 0x00000004
    SAFARI_ECDHE_ECDSA_BUG      = 0x00000040
    DONT_INSERT_EMPTY_FRAGMENTS = 0x00000800

    # Various bug workarounds that should be rather harmless.
    # This used to be `0x000FFFFF` before 0.9.7
    ALL = 0x80000BFF

    NO_QUERY_MTU     = 0x00001000
    COOKIE_EXCHANGE  = 0x00002000
    NO_TICKET        = 0x00004000
    CISCO_ANYCONNECT = 0x00008000

    NO_SESSION_RESUMPTION_ON_RENEGOTIATION = 0x00010000
    NO_COMPRESSION                         = 0x00020000
    ALLOW_UNSAFE_LEGACY_RENEGOTIATION      = 0x00040000
    CIPHER_SERVER_PREFERENCE               = 0x00400000
    TLS_ROLLBACK_BUG                       = 0x00800000

    NO_SSL_V3   = 0x02000000
    NO_TLS_V1   = 0x04000000
    NO_TLS_V1_2 = 0x08000000
    NO_TLS_V1_1 = 0x10000000

    NETSCAPE_CA_DN_BUG              = 0x20000000
    NETSCAPE_DEMO_CIPHER_CHANGE_BUG = 0x40000000
    CRYPTOPRO_TLSEXT_BUG            = 0x80000000

    {% if OPENSSL_110 %}
      MICROSOFT_SESS_ID_BUG            = 0x00000000
      NETSCAPE_CHALLENGE_BUG           = 0x00000000
      NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 0x00000000
      SSLREF2_REUSE_CERT_TYPE_BUG      = 0x00000000
      MICROSOFT_BIG_SSL_V3_BUFFER       = 0x00000000
      SSLEAY_080_CLIENT_DH_BUG         = 0x00000000
      TLS_D5_BUG                       = 0x00000000
      TLS_BLOCK_PADDING_BUG            = 0x00000000
      NO_SSL_V2                         = 0x00000000
      SINGLE_ECDH_USE                  = 0x00000000
      SINGLE_DH_USE                    = 0x00000000
    {% else %}
      MICROSOFT_SESS_ID_BUG            = 0x00000001
      NETSCAPE_CHALLENGE_BUG           = 0x00000002
      NETSCAPE_REUSE_CIPHER_CHANGE_BUG = 0x00000008
      SSLREF2_REUSE_CERT_TYPE_BUG      = 0x00000010
      MICROSOFT_BIG_SSL_V3_BUFFER       = 0x00000020
      SSLEAY_080_CLIENT_DH_BUG         = 0x00000080
      TLS_D5_BUG                       = 0x00000100
      TLS_BLOCK_PADDING_BUG            = 0x00000200
      NO_SSL_V2                         = 0x01000000
      SINGLE_ECDH_USE                  = 0x00080000
      SINGLE_DH_USE                    = 0x00100000
    {% end %}
  end

  @[Flags]
  enum Modes : Int64
    ENABLE_PARTIAL_WRITE       = 0x00000001
    ACCEPT_MOVING_WRITE_BUFFER = 0x00000002
    AUTO_RETRY                 = 0x00000004
    NO_AUTO_CHAIN              = 0x00000008
    RELEASE_BUFFERS            = 0x00000010
    SEND_CLIENTHELLO_TIME      = 0x00000020
    SEND_SERVERHELLO_TIME      = 0x00000040
    SEND_FALLBACK_SCSV         = 0x00000080
  end

  OPENSSL_NPN_UNSUPPORTED = 0
  OPENSSL_NPN_NEGOTIATED  = 1
  OPENSSL_NPN_NO_OVERLAP  = 2

  SSL_TLSEXT_ERR_OK            = 0
  SSL_TLSEXT_ERR_ALERT_WARNING = 1
  SSL_TLSEXT_ERR_ALERT_FATAL   = 2
  SSL_TLSEXT_ERR_NOACK         = 3

  fun tlsv1_method = TLSv1_method : SSLMethod
  fun tlsv1_1_method = TLSv1_1_method : SSLMethod
  fun tlsv1_2_method = TLSv1_2_method : SSLMethod
  fun sslv3_method = SSLv3_method : SSLMethod
  fun sslv23_method = SSLv23_method : SSLMethod
  fun dtlsv1_method = DTLSv1_method : SSLMethod
  fun dtlsv1_2_method = DTLSv1_2_method : SSLMethod

  fun ssl_get_error = SSL_get_error(handle : SSL, ret : Int) : SSLError
  fun ssl_set_bio = SSL_set_bio(handle : SSL, rbio : LibCrypto::Bio*, wbio : LibCrypto::Bio*)
  fun ssl_select_next_proto = SSL_select_next_proto(output : Char**, output_len : Char*, input : Char*, input_len : Int, client : Char*, client_len : Int) : Int
  fun ssl_ctrl = SSL_ctrl(handle : SSL, cmd : Int, larg : Long, parg : Void*) : Long
  fun ssl_free = SSL_free(handle : SSL)
  # fun sslv2_method = SSLv2_method() : SSLMethod

  SSL_VERIFY_NONE                 = 0
  SSL_VERIFY_PEER                 = 1
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2
  X509_FILETYPE_PEM               = 1
  X509_FILETYPE_ASN1              = 2
  X509_FILETYPE_DEFAULT           = 3

  fun ssl_ctx_new = SSL_CTX_new(meth : SSLMethod) : SSLContext
  fun ssl_ctx_free = SSL_CTX_free(ctx : SSLContext)
  fun ssl_ctx_get_ex_new_index = SSL_CTX_get_ex_new_index(argl : Int64, argp : Void*, new_func : Void*,
                                                          dup_func : Void*, free_func : Void*) : Int
  fun ssl_ctx_set_ex_data = SSL_CTX_set_ex_data(ctx : SSLContext, idx : Int, arg : Void*) : Int
  fun ssl_get_ex_data_x509_store_ctx_idx = SSL_get_ex_data_X509_STORE_CTX_idx : Int
  fun x509_store_ctx_get_ex_data = X509_STORE_CTX_get_ex_data(ctx : LibCrypto::X509_STORE_CTX, idx : Int) : Void*
  fun ssl_get_ssl_ctx = SSL_get_SSL_CTX(ssl : Void*) : SSLContext
  fun ssl_ctx_get_ex_data = SSL_CTX_get_ex_data(ctx : SSLContext, idx : Int) : Void*
  fun ssl_ctx_set_verify_depth = SSL_CTX_set_verify_depth(ctx : SSLContext, depth : Int)
  fun ssl_ctx_use_certificate_file = SSL_CTX_use_certificate_file(ctx : SSLContext, file : UInt8*, type : Int) : Int
  fun ssl_ctx_use_certificate = SSL_CTX_use_certificate(ctx : SSLContext, x509 : LibCrypto::X509) : Int
  fun ssl_ctx_use_privatekey = SSL_CTX_use_PrivateKey(ctx : SSLContext, pkey : LibCrypto::EVP_PKEY) : Int
  fun ssl_ctx_check_private_key = SSL_CTX_check_private_key(ctx : SSLContext) : Int
  fun ssl_ctx_set_cipher_list = SSL_CTX_set_cipher_list(ctx : SSLContext, str : UInt8*) : Int
  fun ssl_load_error_strings = SSL_load_error_strings
  fun ssl_library_init = SSL_library_init
  fun ssl_ctx_ctrl = SSL_CTX_ctrl(ctx : SSLContext, cmd : Int, larg : Int64, parg : Void*) : Int64

  @[Raises]
  fun ssl_new = SSL_new(ctx : SSLContext) : SSL

  @[Raises]
  fun ssl_connect = SSL_connect(ssl : SSL) : Int

  @[Raises]
  fun ssl_accept = SSL_accept(ssl : SSL) : Int

  @[Raises]
  fun ssl_read = SSL_read(ssl : SSL, buf : UInt8*, num : Int) : Int

  @[Raises]
  fun ssl_write = SSL_write(ssl : SSL, buf : UInt8*, num : Int) : Int

  @[Raises]
  fun ssl_shutdown = SSL_shutdown(ssl : SSL) : Int

  fun ssl_ctx_new = SSL_CTX_new(method : SSLMethod) : SSLContext
  fun ssl_ctx_free = SSL_CTX_free(context : SSLContext)
  fun ssl_ctx_set_cipher_list = SSL_CTX_set_cipher_list(ctx : SSLContext, ciphers : Char*) : Int
  fun ssl_ctx_use_certificate_chain_file = SSL_CTX_use_certificate_chain_file(ctx : SSLContext, file : UInt8*) : Int
  fun ssl_ctx_use_privatekey_file = SSL_CTX_use_PrivateKey_file(ctx : SSLContext, file : UInt8*, filetype : SSLFileType) : Int
  fun ssl_ctx_get_verify_mode = SSL_CTX_get_verify_mode(ctx : SSLContext) : VerifyMode
  fun ssl_ctx_set_verify = SSL_CTX_set_verify(ctx : SSLContext, mode : VerifyMode, callback : VerifyCallback)
  fun ssl_ctx_set_default_verify_paths = SSL_CTX_set_default_verify_paths(ctx : SSLContext) : Int

  {% if OPENSSL_110 %}
    fun ssl_ctx_get_options = SSL_CTX_get_options(ctx : SSLContext) : ULong
    fun ssl_ctx_set_options = SSL_CTX_set_options(ctx : SSLContext, larg : ULong) : ULong
    fun ssl_ctx_clear_options = SSL_CTX_clear_options(ctx : SSLContext, larg : ULong) : ULong
  {% end %}

  @[Raises]
  fun ssl_ctx_load_verify_locations = SSL_CTX_load_verify_locations(ctx : SSLContext, ca_file : UInt8*, ca_path : UInt8*) : Int

  # Hostname validation for OpenSSL <= 1.0.1
  fun ssl_ctx_set_cert_verify_callback = SSL_CTX_set_cert_verify_callback(ctx : SSLContext, callback : CertVerifyCallback, arg : Void*)

  {% if OPENSSL_110 %}
    fun tls_method = TLS_method : SSLMethod
  {% else %}
    fun ssl_library_init = SSL_library_init
    fun ssl_load_error_strings = SSL_load_error_strings
    fun sslv23_method = SSLv23_method : SSLMethod
  {% end %}

  {% if OPENSSL_102 %}
    alias ALPNCallback = (SSL, Char**, Char*, Char*, Int, Void*) -> Int
    alias X509VerifyParam = LibCrypto::X509VerifyParam

    fun ssl_get0_param = SSL_get0_param(handle : SSL) : X509VerifyParam
    fun ssl_get0_alpn_selected = SSL_get0_alpn_selected(handle : SSL, data : Char**, len : LibC::UInt*) : Void
    fun ssl_ctx_set_alpn_select_cb = SSL_CTX_set_alpn_select_cb(ctx : SSLContext, cb : ALPNCallback, arg : Void*) : Void
    fun ssl_ctx_get0_param = SSL_CTX_get0_param(ctx : SSLContext) : X509VerifyParam
    fun ssl_ctx_set1_param = SSL_CTX_set1_param(ctx : SSLContext, param : X509VerifyParam) : Int
  {% end %}
  fun ssl_free = SSL_free(ssl : SSL)
  fun ssl_set_bio = SSL_set_bio(ssl : SSL, rbio : LibCrypto::BIO, wbio : LibCrypto::BIO)
  fun ssl_get_peer_certificate = SSL_get_peer_certificate(ssl : SSL) : LibCrypto::X509
  fun ssl_renegotiate = SSL_renegotiate(ssl : SSL) : Int
  fun ssl_pending = SSL_pending(ssl : SSL) : Int
  fun ssl_do_handshake = SSL_do_handshake(ssl : SSL) : Int

  SSL_ERROR_NONE             = 0
  SSL_ERROR_SSL              = 1
  SSL_ERROR_SYSCALL          = 5
  SSL_ERROR_WANT_ACCEPT      = 8
  SSL_ERROR_WANT_CONNECT     = 7
  SSL_ERROR_WANT_READ        = 2
  SSL_ERROR_WANT_WRITE       = 3
  SSL_ERROR_WANT_X509_LOOKUP = 4
  SSL_ERROR_ZERO_RETURN      = 6
end

{% unless LibSSL::OPENSSL_110 %}
  LibSSL.ssl_library_init
  LibSSL.ssl_load_error_strings
  LibCrypto.openssl_add_all_algorithms
  LibCrypto.err_load_crypto_strings
{% end %}
