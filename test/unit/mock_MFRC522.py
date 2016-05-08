class MFRC522():

    MI_OK       = 0
    MI_NOTAGERR = 1
    MI_ERR      = 2
    PICC_AUTHENT1A = 0x60
    PICC_AUTHENT1B = 0x61

    return_code = MI_OK

    DEFAULT_SECTOR_CONTENT = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                              0x6B,0x65,0x79,0x20,0x61,0x00,0x78,0x77,0x88,0x69,0x6B,0x65,0x79,0x20,0x62,0x00]
    sector_content = None
    block_content = None

    call_history = []

    def MFRC522_SelectTag(self, tag):
        self.call_history.append({'method': 'MFRC522_SelectTag',
                                  'uid': tag})

    def Auth_Sector(self, authMode, SectorAddr, SectorKey, serNum):
        self.call_history.append({'method': 'Auth_Sector',
                             'keyspec': authMode,
                             'sector': SectorAddr,
                             'key': SectorKey,
                             'uid': serNum})
        if type(self.return_code) == list:
            return self.return_code.pop(0)
        else:
            return self.return_code

    def Read_Sector(self, sectorAddr):
        self.call_history.append({'method': 'Read_Sector',
                                  'sector': sectorAddr})
        if self.sector_content == None:
            return self.MI_ERR, self.sector_content
        else:
            if type(self.return_code) == list:
                return self.return_code.pop(0), self.sector_content
            else:
                return self.return_code, self.sector_content

    def Write_Block(self, blockAddr, writeData):
        self.call_history.append({'method': 'Write_Block',
                                  'block': blockAddr,
                                  'block_content': writeData})
        if type(self.return_code) == list:
            return self.return_code.pop(0), [0x00,0x00,0x00,0x00]
        else:
            return self.return_code, [0x00,0x00,0x00,0x00]

    def MFRC522_StopCrypto1(self):
        self.call_history.append({'method': 'MFRC522_StopCrypto1'})
