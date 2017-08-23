require "spec"
require "openssl"
require "openssl/hmac"

describe OpenSSL::HMAC do
  [
    {:md4, "f3593b56f00b25c8af31d02ddef6d2d0", OpenSSL::Digest::MD4.new},
    {:md5, "0c7a250281315ab863549f66cd8a3a53", OpenSSL::Digest::MD5.new},
    {:sha1, "46b4ec586117154dacd49d664e5d63fdc88efb51", OpenSSL::Digest::SHA1.new},
    {:sha224, "4c1f774863acb63b7f6e9daa9b5c543fa0d5eccf61e3ffc3698eacdd", OpenSSL::Digest::SHA224.new},
    {:sha256, "f9320baf0249169e73850cd6156ded0106e2bb6ad8cab01b7bbbebe6d1065317", OpenSSL::Digest::SHA256.new},
    {:sha384, "3d10d391bee2364df2c55cf605759373e1b5a4ca9355d8f3fe42970471eca2e422a79271a0e857a69923839015877fc6", OpenSSL::Digest::SHA384.new},
    {:sha512, "114682914c5d017dfe59fdc804118b56a3a652a0b8870759cf9e792ed7426b08197076bf7d01640b1b0684df79e4b67e37485669e8ce98dbab60445f0db94fce", OpenSSL::Digest::SHA512.new},
    {:ripemd160, "20d23140503df606c91bda9293f1ad4a23afe509", OpenSSL::Digest::RIPEMD160.new},
  ].each do |algorithm, expected, cipher|
    it "computes #{algorithm}" do
      OpenSSL::HMAC.hexdigest(algorithm, "foo", "bar").should eq(expected)
    end

    it "compute HMAC for #{algorithm} using an instance" do
      next if algorithm == :dss

      hmac = OpenSSL::HMAC.new(algorithm, "foo")
      hmac << "bar"
      hmac.hexdigest.should eq(expected)
    end
  end
end
