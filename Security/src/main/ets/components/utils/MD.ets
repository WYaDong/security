// -*- coding: utf-8 -*-
// Project    : Security
// File       : MD.ets
// Time       ：2024/6/19
// Author     ：ya dong
// Copyright © 2024 CL. All rights reserved.

import { cryptoFramework } from '@kit.CryptoArchitectureKit'
import { buffer } from '@kit.ArkTS'
import { HiLogUtils } from './log/HiLogUtils'

export enum MdEnum {
  SHA1 = "SHA1",
  SHA224 = "SHA224",
  SHA256 = "SHA256",
  SHA384 = "SHA384",
  SHA512 = "SHA512",
  MD5 = "MD5",
  SM3 = "SM3"
}

export class MD {
  async encrypt(sourceString: string, MDEnum: MdEnum): Promise<Uint8Array> {
    try {
      let md = cryptoFramework.createMd(MDEnum)
      await md.update({
        data: new Uint8Array(buffer.from(sourceString, 'utf-8').buffer)
      })
      let mdOutput = await md.digest()
      return mdOutput.data
    }
    catch (e) {
      HiLogUtils.error(JSON.stringify(e))
      return new Uint8Array
    }
  }
}
