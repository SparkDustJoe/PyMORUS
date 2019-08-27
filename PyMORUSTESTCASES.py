from collections import namedtuple;

def PyMorusCases(word_width):
    """
    Return list of namedtuple TestCase 'P AD K IV C T' for either 32-bit or 64-bit flavor of Morus
    Payload, Additional Data, Key, IV/Nonce, Ciphertext, and Tag
    """
    TestCase = namedtuple('TestCase', 'P AD K IV C T');
    assert word_width in (32, 64);
    cases = []
    if (word_width == 32):
        cases.append(TestCase( # 0
            P=None,
            AD=None,
            K=bytes(16),
            IV=bytes(16),
            C=bytearray(0),
            T=bytearray.fromhex('e407fb2255b1314dbfadccfef8102da8')
            ));
        cases.append(TestCase( # 1
            P=bytearray.fromhex('01'),
            AD=None,
            K=bytes(16),
            IV=bytes(16),
            C=bytearray.fromhex('26'),
            T=bytearray.fromhex('ff1c7a66849675f509f428369c06e8d6') 
            ));
        cases.append(TestCase( # 2
            P=None,
            AD=bytearray.fromhex('01'),
            K=bytes(16),
            IV=bytes(16),
            C=bytearray(0),
            T=bytearray.fromhex('1d229cca8ef97ee7c1524326e8dfadba')
           ));
        cases.append(TestCase( # 3
            P=bytearray.fromhex('00'),
            AD=bytearray.fromhex('00'),
            K=bytearray.fromhex('01000000000000000000000000000000'),
            IV=bytes(16),
            C=bytearray.fromhex('d2'),
            T=bytearray.fromhex('4b15ab1cb7cc83791deb6aa9315f4c86')
           ));
        cases.append(TestCase( # 4
            P=bytearray.fromhex('00'),
            AD=bytearray.fromhex('00'),
            K=bytes(16),
            IV=bytearray.fromhex('01000000000000000000000000000000'),
            C=bytearray.fromhex('a7'),
            T=bytearray.fromhex('640b0d536f59b6a8d16bf773b49a5be7') 
            ));
        cases.append(TestCase( # 5
            P=bytearray.fromhex('01010101010101010101010101010101'),
            AD=bytearray.fromhex('01010101010101010101010101010101'),
            K=bytearray.fromhex('01010101010101010101010101010101'),
            IV=bytearray.fromhex('01010101010101010101010101010101'),
            C=bytearray.fromhex('fb5d640c97e673b66abffcc45e72b420'),
            T=bytearray.fromhex('8ed9998761d8900f6d72cc5656186848') 
            ));
        cases.append(TestCase( # 6
            P=bytearray.fromhex('01010101010101010101010101010101'),
            AD=bytearray.fromhex('01010101010101010101010101010101'),
            K=bytearray.fromhex('000102030405060708090a0b0c0d0e0f'),
            IV=bytearray.fromhex('000306090c0f1215181b1e2124272a2d'),
            C=bytearray.fromhex('512b6a397e8f830e5755b2793d384d90'),
            T=bytearray.fromhex('f9842b369701cd29acf2c39907930373') 
            ));
        cases.append(TestCase( # 7
            P=bytearray.fromhex('01010101010101010101010101010101'),
            AD=bytearray.fromhex('01010101010101010101010101010101'),
            K=bytearray.fromhex('01010101010101010101010101010101'),
            IV=bytearray.fromhex('01010101010101010101010101010101'),
            C=bytearray.fromhex('fb5d640c97e673b66abffcc45e72b420'),
            T=bytearray.fromhex('8ed9998761d8900f6d72cc5656186848') 
            ));
        cases.append(TestCase( # 8
            P=bytearray.fromhex('01010101010101010101010101010101'),
            AD=bytearray.fromhex('01010101010101010101010101010101'),
            K=bytearray.fromhex('000102030405060708090a0b0c0d0e0f'),
            IV=bytearray.fromhex('000306090c0f1215181b1e2124272a2d'),
            C=bytearray.fromhex('512b6a397e8f830e5755b2793d384d90'),
            T=bytearray.fromhex('f9842b369701cd29acf2c39907930373') 
            ));
    elif (word_width == 64):
        #64-bit with 16-byte keys
        cases.append(TestCase( # 0
            P=None,
            AD=None,
            K=bytes(16),
            IV=bytes(16),
            C=bytearray(0),
            T=bytearray.fromhex('5bd2cba68ea7e72f6b3d0c155f39f962') 
            ));
        cases.append(TestCase( # 1
            P=bytearray.fromhex('01'),
            AD=None,
            K=bytes(16),
            IV=bytes(16),
            C=bytearray.fromhex('ba'),
            T=bytearray.fromhex('ec1942a315a84695432a1255e6197878') 
            ));
        cases.append(TestCase( # 2
            P=None,
            AD=bytearray.fromhex('01'),
            K=bytes(16),
            IV=bytes(16),
            C=bytearray(0),
            T=bytearray.fromhex('590caa148b848d7614315685377a0d42') 
            ));
        cases.append(TestCase( # 3
            P=bytearray.fromhex('00'),
            AD=bytearray.fromhex('00'),
            K=bytearray.fromhex('01000000000000000000000000000000'),
            IV=bytes(16),
            C=bytearray.fromhex('cf'),
            T=bytearray.fromhex('f9f0a331e3de3293b9dd2e65ba820009') 
            ));
        cases.append(TestCase( # 4
            P=bytearray.fromhex('00'),
            AD=bytearray.fromhex('00'),
            K=bytes(16),
            IV=bytearray.fromhex('01000000000000000000000000000000'),
            C=bytearray.fromhex('09'),
            T=bytearray.fromhex('c957f9ca617876b5205155cd936eb9bb') 
            ));
        cases.append(TestCase( # 5
            P=bytearray.fromhex('01010101010101010101010101010101'),
            AD=bytearray.fromhex('01010101010101010101010101010101'),
            K=bytearray.fromhex('01010101010101010101010101010101'),
            IV=bytearray.fromhex('01010101010101010101010101010101'),
            C=bytearray.fromhex('8831c1e547f7272ccae2ced2997cca44'),
            T=bytearray.fromhex('43c058e1c32e21f82313c50dc95aa68a') 
            ));
        cases.append(TestCase( # 6
            P=bytearray.fromhex('01010101010101010101010101010101'),
            AD=bytearray.fromhex('01010101010101010101010101010101'),
            K=bytearray.fromhex('000102030405060708090a0b0c0d0e0f'),
            IV=bytearray.fromhex('000306090c0f1215181b1e2124272a2d'),
            C=bytearray.fromhex('b64ee39fc045475e97b41bd08277b4cb'),
            T=bytearray.fromhex('e989740eb075f75bd57a43a250f53765') 
            ));
        cases.append(TestCase( # 7
            P=bytearray.fromhex('00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8'),
            AD=bytearray.fromhex('00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969ba0a5aaafb4b9be'),
            K=bytearray.fromhex('000102030405060708090a0b0c0d0e0f'),
            IV=bytearray.fromhex('000306090c0f1215181b1e2124272a2d'),
            C=bytearray.fromhex('0861b4924850e8a945e60ec08a1b04f3c77dd2b05ccb05c05c567be8cdfd458228a390c4117b66d71fade7f89902e4d500389a275cb0ce5685f3a21beb6d6519f465b96f1eaf9eeea2'),
            T=bytearray.fromhex('5e43f30fa0adb318083a795fc23df52c') 
            ));
        cases.append(TestCase( # 8
            P=bytearray.fromhex('00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a'),
            AD=bytearray.fromhex('00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969ba0a5aaafb4b9bec3c8cdd2d7dce1e6ebf0f5faff04090e13181d22272c31363b40454a4f54595e63686d72777c81868b90959a9fa4a9aeb3b8bdc2c7ccd1d6dbe0e5eaeff4f9fe03080d12171c21262b30353a3f44494e53585d62676c71767b80858a8f94999ea3a8adb2b7bcc1c6cbd0d5dadfe4e9eef3f8fd02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989da2a7acb1b6bbc0c5cacfd4d9dee3e8edf2f7fc01060b10151a1f24292e33383d42474c51565b60656a6f74797e83888d92979ca1a6abb0b5babfc4c9ced3d8dde2e7ecf1f6fb00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969ba0a5aaafb4b9bec3c8cdd2d7dce1e6ebf0f5faff04090e13181d22272c31363b40454a4f54595e63686d72777c81868b90959a9fa4a9aeb3b8bdc2c7ccd1d6dbe0e5eaeff4f9fe03080d12171c21262b30353a3f44494e53585d62676c71767b80858a8f94999ea3a8adb2b7bcc1c6cbd0d5dadfe4e9eef3f8fd02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989da2a7acb1b6bbc0c5cacfd4d9dee3e8edf2f7fc01060b10151a1f24292e33383d42474c51565b60656a6f74797e83888d92979ca1a6abb0b5babfc4c9ced3d8dde2e7ecf1f6fb0005'),
            K=bytearray.fromhex('000102030405060708090a0b0c0d0e0f'),
            IV=bytearray.fromhex('000306090c0f1215181b1e2124272a2d'),
            C=bytearray.fromhex('091689ea18d82110c2097aa984977c2258f42f0c12886c1baefb0822b193389429d6214aa951b45870ae279569c162577fe0f7b381251af868da0f9f220c6618dc4f1d6db02914a33b2def945ce0fe771f1302165ab64c06da2bd60f194a198482b24b00b684c102bc5cfaaeda435803a6a772a076cb50371b0cac7c7179ebc1ea7c5924864c56d3857f996af4325a8b24bf2d0d1647c5597d3eb38f46494178166c3c0934af203ac307dd3b73930000b82ddfae385fe0844c9018c69049ab65470ec110cf7f8ad69415c691b4806fdf37bf470ab2ad6e253957f0ce64a09376adec893dbbfd03dd368688f7702692f72cdba5368a05210554d2b6d4d876bf49277353c5347a902045becbfdc1c5346df0abe5e90099332fddd61bccff267919cb07ca0c2595c6c740d299fd37c9c2667d7b444937872fca68e574a00c1e558023f8a4a4e22fabfdbc45dfb0ef5af173d104852a82dc5bf6cea4cdb2ede955f2ef29b1b642e55dff38455b8dd572bc734da52c9325bea8061fd30ebafef1ceafdb877b5f88f3a38423018088fd91854f5f1edcb09ca14d404862bab3b242e820504f400931e1d7d83d6c8f9f3c95b1f9e984f94d6afe1276ad5c8a70d364e36c4d9d43f12c586d0813e98584eacc423f476bbbdf23536dbafab19447fbf628974c6973a653e8c4af61c8eadc1eb844f87206fbb6eeeba9224e9b3d5536df047eb8fef6aa2403ca64c191c6c6c50e714473cc97ac0435154fd7dd958df88e30eb27bc42069bda9f03a3e5c1fcf358b1b10ef557b2b1658c4972df71f2d2069e7520dc791ca5fd23deb43178b6ac32498b998d3f9a792a8b6d4a6454a18d7b7fca879262f3ca567e055e7c30575e48bd24efdb49fb3898d604c48ecb0d0333e400c95d2dca5b816637c7ad6622bbf2146d1e7162535141ba1bb8db7171c6158f2f7e9363f27c29a72c02cbfb2d38463288dac1e4916ac9f0b4084cba34d35d37856a7505e5974dfeb9a24b6dc7fd6b067eb5121244748452443a8fdbbd86e87986f5fc9952c68d100bd4c62c12b40b1dcd75291b8715775c785228c3daaae3ae5de25d96c2cdf6992c72bebd19bdaebef70c53116e15826f58a58ea4f25cc12dae10f8437636436ecd05bde3f470a4a97aba0840b37b9609722bcd81d55fa7e6d8be38f9be11b087a98cafad28f33154ead815a057629715985d183b0a828e0391cab9744265b84fdad5de2f0c188255e26778c2e3fbd8cd72e2e8ae9246c6a6fa4fd6ec9472c03c4fbdfea82d35cb32593e0175dc65438fd769bfcb62bacb368c246db2d6031910df0d5bfd3ca16f449a58e444a502147024544363ac6cc691b6cd5614a215b9d7bdfa151ee4412f84a2ff51084102777e3a1d5bd0420aac5f4db96465212cc0bd66d00a4494b9ec73d83453db49f77c30b253de79c8b337668c681766f8631d9a'),
            T=bytearray.fromhex('5397afda1e9784245d0a915f84b7f510') 
            ));
        #64-bit but now with 32-byte keys
        cases.append(TestCase( # 9 (0)
            P=None,
            AD=None,
            K=bytes(32),
            IV=bytes(16),
            C=bytearray(0),
            T=bytearray.fromhex('5bd2cba68ea7e72f6b3d0c155f39f962') 
            ));
        cases.append(TestCase( # 10 (1)
            P=bytearray.fromhex('01'),
            AD=None,
            K=bytes(32),
            IV=bytes(16),
            C=bytearray.fromhex('ba'),
            T=bytearray.fromhex('ec1942a315a84695432a1255e6197878') 
            ));
        cases.append(TestCase( # 11 (2)
            P=None,
            AD=bytearray.fromhex('01'),
            K=bytes(32),
            IV=bytes(16),
            C=bytearray(0),
            T=bytearray.fromhex('590caa148b848d7614315685377a0d42') 
            ));
        cases.append(TestCase( # 12 (3)
            P=bytearray.fromhex('00'),
            AD=bytearray.fromhex('00'),
            K=bytearray.fromhex('0100000000000000000000000000000000000000000000000000000000000000'),
            IV=bytes(16),
            C=bytearray.fromhex('99'),
            T=bytearray.fromhex('3452c0f33fb548d09f7bb50a53dd2f72') 
            ));
        cases.append(TestCase( # 13 (4)
            P=bytearray.fromhex('00'),
            AD=bytearray.fromhex('00'),
            K=bytes(32),
            IV=bytearray.fromhex('01000000000000000000000000000000'),
            C=bytearray.fromhex('09'),
            T=bytearray.fromhex('c957f9ca617876b5205155cd936eb9bb') 
            ));
        cases.append(TestCase( # 14 (5)
            P=bytearray.fromhex('01010101010101010101010101010101'),
            AD=bytearray.fromhex('01010101010101010101010101010101'),
            K=bytearray.fromhex('0101010101010101010101010101010101010101010101010101010101010101'),
            IV=bytearray.fromhex('01010101010101010101010101010101'),
            C=bytearray.fromhex('8831c1e547f7272ccae2ced2997cca44'),
            T=bytearray.fromhex('43c058e1c32e21f82313c50dc95aa68a') 
            ));
        cases.append(TestCase( # 15 (6)
            P=bytearray.fromhex('01010101010101010101010101010101'),
            AD=bytearray.fromhex('01010101010101010101010101010101'),
            K=bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
            IV=bytearray.fromhex('000306090c0f1215181b1e2124272a2d'),
            C=bytearray.fromhex('aecb6f5991a11746831740e4d45b6c26'),
            T=bytearray.fromhex('c3107488470f05e6828472ac0264045d') 
            ));
        cases.append(TestCase( # 16 (7)
            P=bytearray.fromhex('00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8'),
            AD=bytearray.fromhex('00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969ba0a5aaafb4b9be'),
            K=bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
            IV=bytearray.fromhex('000306090c0f1215181b1e2124272a2d'),
            C=bytearray.fromhex('3e440c73993c55074d4749d6cd8ceddebb95ea8d2387062237349123c75959bfa3ff44b18395a0bfc834d5f2de24845bffdba576afab00e798ad5a166689288373f84ead85eb77aa2d'),
            T=bytearray.fromhex('f3166bbf6f94a1932b4b2471e8437206') 
            ));
        cases.append(TestCase( # 17 (8)
            P=bytearray.fromhex('00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7fe050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5ecf3fa01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a'),
            AD=bytearray.fromhex('00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969ba0a5aaafb4b9bec3c8cdd2d7dce1e6ebf0f5faff04090e13181d22272c31363b40454a4f54595e63686d72777c81868b90959a9fa4a9aeb3b8bdc2c7ccd1d6dbe0e5eaeff4f9fe03080d12171c21262b30353a3f44494e53585d62676c71767b80858a8f94999ea3a8adb2b7bcc1c6cbd0d5dadfe4e9eef3f8fd02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989da2a7acb1b6bbc0c5cacfd4d9dee3e8edf2f7fc01060b10151a1f24292e33383d42474c51565b60656a6f74797e83888d92979ca1a6abb0b5babfc4c9ced3d8dde2e7ecf1f6fb00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969ba0a5aaafb4b9bec3c8cdd2d7dce1e6ebf0f5faff04090e13181d22272c31363b40454a4f54595e63686d72777c81868b90959a9fa4a9aeb3b8bdc2c7ccd1d6dbe0e5eaeff4f9fe03080d12171c21262b30353a3f44494e53585d62676c71767b80858a8f94999ea3a8adb2b7bcc1c6cbd0d5dadfe4e9eef3f8fd02070c11161b20252a2f34393e43484d52575c61666b70757a7f84898e93989da2a7acb1b6bbc0c5cacfd4d9dee3e8edf2f7fc01060b10151a1f24292e33383d42474c51565b60656a6f74797e83888d92979ca1a6abb0b5babfc4c9ced3d8dde2e7ecf1f6fb0005'),
            K=bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'),
            IV=bytearray.fromhex('000306090c0f1215181b1e2124272a2d'),
            C=bytearray.fromhex('a4e9b76daa84ea04c2a945e8728b3c476f326672d31e8175763026aa4299e741ebdc8b1f2fe7806b5d9aed247a9cde143f96072faeecfe9c163453b4f4997b1320abfa545e0d4fd41c2baea1cfa9dae3919d4fa79faef0d8b63a358f9547d717a0112949c6434dfe765c75737c03b1056333234194027d4d769fbc41728d0eff5222fbce4337940158722904150c1dffbd0b0c2b425f5fe40c957d255997f6f1c197838812422eed0b42a53b9453d945b0aad293ecb9995a73ade4be202dab53f418b7bb66c62ce93739cc35b9654c65d636fb590787c4f22eb22f7a5e8a7ae78861300ac6adcddd2996a19f972357de8fc67d831f58bf79841ae1ece222dff2fb01f914ed73f10381050e2124536984a7b4dbf34e9a34d5a89c0786a96e2744af0e8b52f078be56657427786cbba83d67a4ad0c86d1f1868794b0cba951cf6c82db3ac4515387ffa3dfe150d16cf12b9e6dc5b7e5363a0de44ccfbb4a7af903e598b17d3672df37edb021d40a4c4621ca63008f9f01cbfdd4c295e0052fe0ffa4888da92554b3a61c374c5012f2930c3d109d94fd71d490f84bc4b7a4c5d7d55ac47418e21bc71172b4a8e953a198b84b63b617ae7734b9a446669682f467b8ccd4d590e9a35f87cc470068a7474aeb6303b0a4c2c2e1f75466ba928b2dbb1f763ad52ff8f022998733c38f2782a2a0e13f4eb7ce26777bfd76f9a08d589e416c8d24a3f757d6429a016b17b3e9f93f6ff094b6d7df4fd8ea829be3414a4c33f1a00a32823eb860b27de16259db37b5b570eb33e0b4f12eb155d46dcaafae222b6473b3c26ec180f445a9fbdad924d36b48fef3ac92f6a57c5a59081f93715b31127617060afea2246d17e263db3c5125f792aea3dca2c48f9886a170ebe21458b1fd021340c3ee0e08f729d0aec2d80c270488708cbcec32efc602cfd07996a10b9e5f31488c75d0cb73ace8ee23c4118b9e730d043ba34c4997853d6943153234cbd06f5487b0fafc20318efbed01261d3dbd874b4b1b449b529f6175dbf07738252baf57106fe8c900c22605a6c9935b623da4020b243e3755d1938e15e135b124675055133411918517b0a25ab0106e4c3f04313d82b75d2cd13908628ba267c5d91d04d49a7f592d64f7a6f5a19aabc6904da0402bb1e456356ad0c4261338e0c810789ab6cc95b228123bfc9c1e6b6075c3c4f571dd0bdbf3399e70a49edc2532c610bb411bfe4a6b79abf909599235721d7b4ce09966aa726fd2b3d224428b67e719c412b6cde3d46fd0faffe86d245e0745bd41d3181a768f640e59d7b3242c22d7d8a62cd68e5bd736f5379ad19896fd3bce1adae3c994aab45792a98eef931d700000f6081a8d1040972682f50382aa1db59352adf5593685e4ce813fba616f0c546915d897565c3dd0239bb2dfedf364db8f07bfb431d19acb0d67454fa38f28da'),
            T=bytearray.fromhex('2463e5794bc56c06e9aa7da25dbe5dfd') 
            ));
    else:
        return None;
    return cases;

if (__name__ == "__main__"):
    print(len(PyMorusCases(32)));
    print(len(PyMorusCases(64)));
    print("PyMorusTESTCASES.py **NOT A STANDALONE MODULE!**");
