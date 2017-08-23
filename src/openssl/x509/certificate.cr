require "openssl/lib_crypto"
require "openssl/bio/mem_bio"
require "./extension"
require "./name"

# :nodoc:
module OpenSSL::X509
  # :nodoc:
  class Certificate
    def initialize
      @cert = LibCrypto.x509_new
      raise Error.new("X509_new") if @cert.null?
    end

    def initialize(cert : LibCrypto::X509)
      @cert = LibCrypto.x509_dup(cert)
      raise Error.new("X509_dup") if @cert.null?
    end

    def self.from_pem(io)
      bio = MemBIO.new
      IO.copy(io, bio)
      x509 = LibCrypto.pem_read_bio_x509(bio, nil, nil, nil)
      new(x509)
    end

    def finalize
      LibCrypto.x509_free(@cert)
    end

    def dup
      self.class.new(@cert)
    end

    def to_unsafe
      @cert
    end

    def subject
      subject = LibCrypto.x509_get_subject_name(@cert)
      raise Error.new("X509_get_subject_name") if subject.null?
      Name.new(subject)
    end

    # Sets the subject.
    #
    # Refer to `Name.parse` for the format.
    def subject=(subject : String)
      self.subject = Name.parse(subject)
    end

    def subject=(subject : Name)
      ret = LibCrypto.x509_set_subject_name(@cert, subject)
      raise Error.new("X509_set_subject_name") if ret == 0
      subject
    end

    def extensions
      count = LibCrypto.x509_get_ext_count(@cert)
      Array(Extension).new(count) do |i|
        Extension.new(LibCrypto.x509_get_ext(@cert, i))
      end
    end

    def add_extension(extension : Extension)
      ret = LibCrypto.x509_add_ext(@cert, extension, -1)
      raise Error.new("X509_add_ext") if ret.null?
      extension
    end

    def public_key
      PKey::RSA.new(LibCrypto.x509_get_pubkey(self), false)
    end

    def subject_name
      handle = LibCrypto.x509_get_subject_name(self)
      Name.new LibCrypto.x509_name_dup(handle)
    end

    def fingerprint(digest : OpenSSL::Digest = OpenSSL::Digest.new("SHA1"))
      slice = Slice(UInt8).new digest.digest_size
      if LibCrypto.x509_digest(self, digest.to_unsafe_md, slice, out len) == 0
        raise Error.new("X509 digest compution failed")
      end
      if len != slice.size
        raise Error.new("X509 fingerprint is corrupted")
      end
      slice
    end

    def fingerprint_hex(digest : OpenSSL::Digest = OpenSSL::Digest.new("SHA1"))
      DigestBase.hexdump(fingerprint(digest))
    end

    def verify(pkey)
      ret = LibCrypto.x509_verify(self, pkey)
      if ret < 0
        raise Error.new("X509 verification failed")
      end
      ret > 0
    end

    def to_pem(io)
      bio = MemBIO.new
      LibCrypto.pem_write_bio_x509(bio, self)
      IO.copy(bio, io)
    end

    def to_pem
      io = IO::Memory.new
      to_pem(io)
      io.to_s
    end
  end
end
