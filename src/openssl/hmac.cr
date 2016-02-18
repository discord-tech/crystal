require "./lib_crypto"
require "./digest/digest_base"

# Allows computing Hash-based Message Authentication Code (HMAC).
#
# It is a type of message authentication code (MAC)
# involving a hash function in combination with a key.
#
# HMAC can be used to verify the integrity of a message as well as the authenticity.
#
# See also [RFC2104](https://tools.ietf.org/html/rfc2104.html).
class OpenSSL::HMAC
  # Returns the HMAC digest of *data* using the secret *key*.
  #
  # It may contain non-ASCII bytes, including NUL bytes.
  #
  # *algorithm* is a `Symbol` of a supported digest algorithm:
  # * `:md4`.
  # * `:md5`.
  # * `:ripemd160`.
  # * `:sha1`.
  # * `:sha224`.
  # * `:sha256`.
  # * `:sha384`.
  # * `:sha512`.
  def self.digest(algorithm : Symbol, key, data) : Bytes
    evp = case algorithm
          when :md4       then LibCrypto.evp_md4
          when :md5       then LibCrypto.evp_md5
          when :ripemd160 then LibCrypto.evp_ripemd160
          when :sha1      then LibCrypto.evp_sha1
          when :sha224    then LibCrypto.evp_sha224
          when :sha256    then LibCrypto.evp_sha256
          when :sha384    then LibCrypto.evp_sha384
          when :sha512    then LibCrypto.evp_sha512
          else                 raise "Unsupported digest algorithm: #{algorithm}"
          end
    key_slice = key.to_slice
    data_slice = data.to_slice
    buffer = Bytes.new(128)
    LibCrypto.hmac(evp, key_slice, key_slice.size, data_slice, data_slice.size, buffer, out buffer_len)
    buffer[0, buffer_len.to_i]
  end

  # Returns the HMAC digest of *data* using the secret *key*,
  # formatted as a hexadecimal string. This is neccesary to safely transfer
  # the digest where binary messages are not allowed.
  #
  # See also `#digest`.
  def self.hexdigest(algorithm : Symbol, key, data) : String
    digest(algorithm, key, data).hexstring
  end

  Error = Class.new(OpenSSL::Error)

  include DigestBase

  def initialize
    @ctx = LibCrypto::HMAC_CTX_Struct.new
    LibCrypto.hmac_ctx_init(self)
  end

  def finalize
    LibCrypto.hmac_ctx_cleanup(self)
  end

  def self.new(key, digest)
    new.tap do |hmac|
      LibCrypto.hmac_init_ex(hmac, key.to_unsafe as Pointer(Void), key.bytesize, digest.to_unsafe_md, nil)
    end
  end

  def clone
    HMAC.new.tap do |hmac|
      LibCrypto.hmac_ctx_copy(hmac, self)
    end
  end

  def reset
    LibCrypto.hmac_init(self, nil, 0, nil)
    self
  end

  def update(data)
    LibCrypto.hmac_update(self, data, LibC::SizeT.new(data.bytesize))
    self
  end

  protected def finish
    size = LibCrypto.evp_md_size(@ctx.md)
    data = Slice(UInt8).new(size)
    LibCrypto.hmac_final(self, data, out len)
    data[0, len.to_i32]
  end

  def to_unsafe
    pointerof(@ctx)
  end
end
