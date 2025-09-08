//
//  AES_256_CBC_ERR.swift
//  AES_256_CBC
//
//  Created by ld on 2025/9/8.
//

import Foundation

public enum AES256CBCErr: Error, Sendable {
    case encrypt(AES256CBCDetailedErr)
    case decrypt(AES256CBCDetailedErr)
}

public enum AES256CBCDetailedErr: CustomStringConvertible, Sendable {
    case keyLenght
    case ivLenght
    case encrypt_faild(Int32)
    case decrypt_faild(Int32)
    case invalid_content
    
    public var description: String {
        switch self {
        case .keyLenght:    "The key length must be 32 bytes"
        case .ivLenght:     "The length of IV must be 16 bytes"
        case .encrypt_faild(let code): "Encryption failed, error code: \(code)"
        case .decrypt_faild(let code): "Decryption failed, error code: \(code)"
        case .invalid_content: "Invalid content"
        }
    }
}
