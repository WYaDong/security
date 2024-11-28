// -*- coding: utf-8 -*-
// Project    : Security
// File       : SecurityResult.ets
// Time       ：2024/6/19
// Author     ：ya dong
// Copyright © 2024 CL. All rights reserved.

import { util } from '@kit.ArkTS'
import { HiLogUtils } from './utils/log/HiLogUtils'

export class SecurityResult {
  private _data: Uint8Array
  code: number = 0

  constructor(initData: Uint8Array) {
    this._data = initData
    if (initData && initData.length > 0) {
      this.code = 100
    }
  }

  data(): Uint8Array {
    return this._data
  }

  utf8String(): string {
    try {
      return util.TextDecoder.create().decodeToString(this._data)
    } catch (e) {
      HiLogUtils.error(JSON.stringify(e))
      return ''
    }
  }

  hex(): string {
    return this.hexLower().toUpperCase()
  }

  hexLower(): string {
    return this._data.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '')
  }

  base64(): string {
    try {
      return new util.Base64Helper().encodeToStringSync(this._data)
    } catch (e) {
      HiLogUtils.error(JSON.stringify(e))
      return ''
    }
  }
}

