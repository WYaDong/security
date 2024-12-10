// -*- coding: utf-8 -*-
// Project    : Security
// File       : Security.ets
// Time       ：2024/6/19
// Author     ：ya dong
// Copyright © 2024 CL. All rights reserved.

import { HMACEnum, HMac } from './utils/HMac'
import { SecurityResult } from './SecurityResult'
import { AES, AESMSEnum, AESPKCSEnum } from './utils/AES'
import { MdEnum, MD } from './utils/MD'
import { buffer } from '@kit.ArkTS'
import { HiLogUtils } from './utils/log/HiLogUtils'

export enum AESKeyEnum {
  AES128 = 'AES128',
  AES192 = 'AES192',
  AES256 = 'AES256'
}

export class Security {
  static async hMacSha1(encryptString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(encryptString, keyString, HMACEnum.SHA1)
    return new SecurityResult(shaData)
  }

  static async hMacSha224(encryptString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(encryptString, keyString, HMACEnum.SHA224)
    return new SecurityResult(shaData)
  }

  static async hMacSha256(encryptString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(encryptString, keyString, HMACEnum.SHA256)
    return new SecurityResult(shaData)
  }

  static async hMacSha384(encryptString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(encryptString, keyString, HMACEnum.SHA384)
    return new SecurityResult(shaData)
  }

  static async hMacSha512(encryptString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(encryptString, keyString, HMACEnum.SHA512)
    return new SecurityResult(shaData)
  }

  static async hMacSM3(encryptString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(encryptString, keyString, HMACEnum.SM3)
    return new SecurityResult(shaData)
  }


  static async sha1(encryptString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(encryptString, MdEnum.SHA1)
    return new SecurityResult(shaData)
  }

  static async sha224(encryptString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(encryptString, MdEnum.SHA224)
    return new SecurityResult(shaData)
  }

  static async sha256(encryptString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(encryptString, MdEnum.SHA256)
    return new SecurityResult(shaData)
  }

  static async sha384(encryptString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(encryptString, MdEnum.SHA384)
    return new SecurityResult(shaData)
  }

  static async sha512(encryptString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(encryptString, MdEnum.SHA512)
    return new SecurityResult(shaData)
  }

  static async sm3(encryptString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(encryptString, MdEnum.SM3)
    return new SecurityResult(shaData)
  }

  static async md5(encryptString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(encryptString, MdEnum.MD5)
    return new SecurityResult(shaData)
  }

  //  aes cbc模式
  static async aesEncrypt(encryptString: string, key: string, iv: string): Promise<SecurityResult> {
    let shaData =
      await new AES().encryptWithString(encryptString, key, iv, AESKeyEnum.AES128, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesEncryptWithData(sourceData: Uint8Array, keyData: Uint8Array,
    ivData: Uint8Array): Promise<SecurityResult> {
    let shaData =
      await new AES().encryptWithData(sourceData, keyData, ivData, AESKeyEnum.AES128, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesDecrypt(decryptData: Uint8Array, key: string, iv: string): Promise<SecurityResult> {
    let shaData =
      await new AES().decryptWithString(decryptData, key, iv, AESKeyEnum.AES128, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesDecryptWithHexString(decrypt: string, key: string, iv: string): Promise<SecurityResult> {
    try {
      let shaData = await new AES().decryptWithString(new Uint8Array(buffer.from(decrypt, 'hex').buffer), key, iv,
        AESKeyEnum.AES128, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
      return new SecurityResult(shaData)
    } catch (e) {
      HiLogUtils.error(JSON.stringify(e))
      return new SecurityResult(new Uint8Array())
    }
  }

  static async aesDecryptWithData(decryptData: Uint8Array, keyData: Uint8Array,
    ivData: Uint8Array): Promise<SecurityResult> {
    let shaData =
      await new AES().decryptWithData(decryptData, keyData, ivData, AESKeyEnum.AES128, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesEncryptWithSymAlgName(encryptString: string, key: string, iv: string,
    symAlgName: AESKeyEnum): Promise<SecurityResult> {
    let shaData =
      await new AES().encryptWithString(encryptString, key, iv, symAlgName, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesEncryptWithSymAlgNameWithData(sourceData: Uint8Array, keyData: Uint8Array, ivData: Uint8Array,
    symAlgName: AESKeyEnum): Promise<SecurityResult> {
    let shaData =
      await new AES().encryptWithData(sourceData, keyData, ivData, symAlgName, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesDecryptWithSymAlgName(decryptData: Uint8Array, key: string, iv: string,
    symAlgName: AESKeyEnum): Promise<SecurityResult> {
    let shaData = await new AES().decryptWithString(decryptData, key, iv, symAlgName, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesDecryptWithHexStringWithSymAlgName(decrypt: string, key: string, iv: string,
    symAlgName: AESKeyEnum): Promise<SecurityResult> {
    try {
      let shaData = await new AES().decryptWithString(new Uint8Array(buffer.from(decrypt, 'hex').buffer), key, iv,
        symAlgName, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
      return new SecurityResult(shaData)
    } catch (e) {
      HiLogUtils.error(JSON.stringify(e))
      return new SecurityResult(new Uint8Array())
    }
  }

  static async aesDecryptWithSymAlgNameWithData(decryptData: Uint8Array, keyData: Uint8Array, ivData: Uint8Array,
    symAlgName: AESKeyEnum): Promise<SecurityResult> {
    let shaData =
      await new AES().decryptWithData(decryptData, keyData, ivData, symAlgName, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }
}