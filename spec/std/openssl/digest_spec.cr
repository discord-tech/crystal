require "spec"
require "../../../src/openssl"

describe OpenSSL::Digest do
  [
    {"SHA1", "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33", OpenSSL::Digest::SHA1.new},
    {"SHA256", "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", OpenSSL::Digest::SHA256.new},
    {"SHA512", "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7", OpenSSL::Digest::SHA512.new},
  ].each do |algorithm, expected, cipher|
    it "should be able to calculate #{algorithm}" do
      digest = OpenSSL::Digest.new(algorithm)
      digest << "foo"
      digest.hexdigest.should eq(expected)
    end

    it "should be able to instantiate specific type" do
      digest = cipher
      digest << "foo"
      digest.hexdigest.should eq(expected)
    end
  end

  it "raises a UnsupportedError if digest is unsupported" do
    expect_raises OpenSSL::Digest::UnsupportedError do
      OpenSSL::Digest.new("unsupported")
    end
  end

  it "returns the digest size" do
    OpenSSL::Digest.new("SHA1").digest_size.should eq 20
    OpenSSL::Digest.new("SHA256").digest_size.should eq 32
  end

  it "returns the block size" do
    OpenSSL::Digest.new("SHA1").block_size.should eq 64
    OpenSSL::Digest.new("SHA256").block_size.should eq 64
  end

  it "correctly reads from IO" do
    r, w = IO.pipe
    digest = OpenSSL::Digest.new("SHA256")

    w << "foo"
    w.close
    digest << r
    r.close

    digest.hexdigest.should eq("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
  end
end
