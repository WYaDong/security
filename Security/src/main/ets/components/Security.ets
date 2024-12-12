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
  static async hMacSha1(sourceString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(sourceString, keyString, HMACEnum.SHA1)
    return new SecurityResult(shaData)
  }

  static async hMacSha224(sourceString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(sourceString, keyString, HMACEnum.SHA224)
    return new SecurityResult(shaData)
  }

  static async hMacSha256(sourceString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(sourceString, keyString, HMACEnum.SHA256)
    return new SecurityResult(shaData)
  }

  static async hMacSha384(sourceString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(sourceString, keyString, HMACEnum.SHA384)
    return new SecurityResult(shaData)
  }

  static async hMacSha512(sourceString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(sourceString, keyString, HMACEnum.SHA512)
    return new SecurityResult(shaData)
  }

  static async hMacSM3(sourceString: string, keyString: string): Promise<SecurityResult> {
    let shaData = await new HMac().hMac(sourceString, keyString, HMACEnum.SM3)
    return new SecurityResult(shaData)
  }


  static async sha1(sourceString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(sourceString, MdEnum.SHA1)
    return new SecurityResult(shaData)
  }

  static async sha224(sourceString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(sourceString, MdEnum.SHA224)
    return new SecurityResult(shaData)
  }

  static async sha256(sourceString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(sourceString, MdEnum.SHA256)
    return new SecurityResult(shaData)
  }

  static async sha384(sourceString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(sourceString, MdEnum.SHA384)
    return new SecurityResult(shaData)
  }

  static async sha512(sourceString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(sourceString, MdEnum.SHA512)
    return new SecurityResult(shaData)
  }

  static async sm3(sourceString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(sourceString, MdEnum.SM3)
    return new SecurityResult(shaData)
  }

  static async md5(sourceString: string): Promise<SecurityResult> {
    let shaData = await new MD().md(sourceString, MdEnum.MD5)
    return new SecurityResult(shaData)
  }

  //  aes cbc模式
  static async aesEncrypt(sourceString: string, key: string, iv: string): Promise<SecurityResult> {
    let shaData =
      await new AES().encryptWithString(sourceString, key, iv, AESKeyEnum.AES128, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesEncryptWithData(sourceData: Uint8Array, keyData: Uint8Array,
    ivData: Uint8Array): Promise<SecurityResult> {
    let shaData =
      await new AES().encryptWithData(sourceData, keyData, ivData, AESKeyEnum.AES128, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesDecrypt(sourceData: Uint8Array, key: string, iv: string): Promise<SecurityResult> {
    let shaData =
      await new AES().decryptWithString(sourceData, key, iv, AESKeyEnum.AES128, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesDecryptWithHexString(hexString: string, key: string, iv: string): Promise<SecurityResult> {
    try {
      let shaData = await new AES().decryptWithString(new Uint8Array(buffer.from(hexString, 'hex').buffer), key, iv,
        AESKeyEnum.AES128, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
      return new SecurityResult(shaData)
    } catch (e) {
      HiLogUtils.error("code: " + e.code + " message: " + e.message)
      return new SecurityResult(new Uint8Array())
    }
  }

  static async aesDecryptWithData(sourceData: Uint8Array, keyData: Uint8Array,
    ivData: Uint8Array): Promise<SecurityResult> {
    let shaData =
      await new AES().decryptWithData(sourceData, keyData, ivData, AESKeyEnum.AES128, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesEncryptWithSymAlgName(sourceString: string, key: string, iv: string,
    symAlgName: AESKeyEnum): Promise<SecurityResult> {
    let shaData =
      await new AES().encryptWithString(sourceString, key, iv, symAlgName, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesEncryptWithSymAlgNameWithData(sourceData: Uint8Array, keyData: Uint8Array, ivData: Uint8Array,
    symAlgName: AESKeyEnum): Promise<SecurityResult> {
    let shaData =
      await new AES().encryptWithData(sourceData, keyData, ivData, symAlgName, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesDecryptWithSymAlgName(sourceData: Uint8Array, key: string, iv: string,
    symAlgName: AESKeyEnum): Promise<SecurityResult> {
    let shaData = await new AES().decryptWithString(sourceData, key, iv, symAlgName, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }

  static async aesDecryptWithHexStringWithSymAlgName(hexString: string, key: string, iv: string,
    symAlgName: AESKeyEnum): Promise<SecurityResult> {
    try {
      let shaData = await new AES().decryptWithString(new Uint8Array(buffer.from(hexString, 'hex').buffer), key, iv,
        symAlgName, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
      return new SecurityResult(shaData)
    } catch (e) {
      HiLogUtils.error("code: " + e.code + " message: " + e.message)
      return new SecurityResult(new Uint8Array())
    }
  }

  static async aesDecryptWithSymAlgNameWithData(sourceData: Uint8Array, keyData: Uint8Array, ivData: Uint8Array,
    symAlgName: AESKeyEnum): Promise<SecurityResult> {
    let shaData =
      await new AES().decryptWithData(sourceData, keyData, ivData, symAlgName, AESMSEnum.CBC, AESPKCSEnum.PKCS7)
    return new SecurityResult(shaData)
  }
}