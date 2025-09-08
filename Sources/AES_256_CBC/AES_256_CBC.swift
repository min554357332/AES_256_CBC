import Foundation
import CryptoKit
import CommonCrypto

public struct AES256CBC {
    private static func check(
        key: Data,
        iv: Data
    ) throws(AES256CBCErr) {
        if key.count != kCCKeySizeAES256 { throw .encrypt(.keyLenght) }
        if iv.count != kCCBlockSizeAES128 { throw .encrypt(.ivLenght) }
    }
}


// MARK: - encrypt & decrypt
public extension AES256CBC {
    /// AES-256-CBC 加密
    /// - Parameters:
    ///   - data: 要加密的数据
    ///   - key: 256位密钥 (32字节)
    ///   - iv: 初始化向量 (16字节)
    /// - Returns: 加密后的数据
    static func encrypt(
        data: Data,
        key: Data,
        iv: Data
    ) async throws(AES256CBCErr) -> Data {
        try AES256CBC.check(key: key, iv: iv)
        
        let dataLength = data.count
        let bufferLength = dataLength + kCCBlockSizeAES128
        var buffer = Data(count: bufferLength)
        var numBytesEncrypted: size_t = 0
        
        let cryptStatus = buffer.withUnsafeMutableBytes { bufferPtr in
            data.withUnsafeBytes { dataPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr.baseAddress,
                            key.count,
                            ivPtr.baseAddress,
                            dataPtr.baseAddress,
                            dataLength,
                            bufferPtr.baseAddress,
                            bufferLength,
                            &numBytesEncrypted
                        )
                    }
                }
            }
        }
        
        guard cryptStatus == kCCSuccess else {
            throw .encrypt(.encrypt_faild(cryptStatus))
        }
        
        return Data(buffer.prefix(numBytesEncrypted))
    }
    
    /// AES-256-CBC 解密
    /// - Parameters:
    ///   - data: 要解密的数据
    ///   - key: 256位密钥 (32字节)
    ///   - iv: 初始化向量 (16字节)
    /// - Returns: 解密后的数据，失败返回nil
    static func decrypt(
        data: Data,
        key: Data,
        iv: Data
    ) async throws(AES256CBCErr) -> Data {
        try AES256CBC.check(key: key, iv: iv)
        
        let dataLength = data.count
        let bufferLength = dataLength + kCCBlockSizeAES128
        var buffer = Data(count: bufferLength)
        var numBytesDecrypted: size_t = 0
        
        let cryptStatus = buffer.withUnsafeMutableBytes { bufferPtr in
            data.withUnsafeBytes { dataPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr.baseAddress,
                            key.count,
                            ivPtr.baseAddress,
                            dataPtr.baseAddress,
                            dataLength,
                            bufferPtr.baseAddress,
                            bufferLength,
                            &numBytesDecrypted
                        )
                    }
                }
            }
        }
        
        guard cryptStatus == kCCSuccess else {
            throw .decrypt(.decrypt_faild(cryptStatus))
        }
        
        return Data(buffer.prefix(numBytesDecrypted))
    }
    
}

// MARK: - generate
public extension AES256CBC {
    /// 生成随机密钥
    /// - Returns: 32字节的随机密钥
    static func generateRandomKey() -> Data {
        var keyData = Data(count: kCCKeySizeAES256)
        _ = keyData.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, kCCKeySizeAES256, bytes.baseAddress!)
        }
        return keyData
    }
    
    /// 生成随机IV
    /// - Returns: 16字节的随机IV
    static func generateRandomIV() -> Data {
        var ivData = Data(count: kCCBlockSizeAES128)
        _ = ivData.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, kCCBlockSizeAES128, bytes.baseAddress!)
        }
        return ivData
    }
    
    /// 从字符串生成密钥
    /// - Parameter password: 密码字符串
    /// - Returns: 32字节的密钥
    static func keyFromPassword(_ password: String) -> Data {
        let data = password.data(using: .utf8) ?? Data()
        return SHA256.hash(data: data).withUnsafeBytes { Data($0) }
    }
}
