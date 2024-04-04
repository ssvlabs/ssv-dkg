package fixtures

import "github.com/bloxapp/ssv-dkg/pkgs/wire"

var (
	TestOperator1Proof4Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("246e4ce7e8eee18ea7b7342d3bc7c4c7f9b092c6f41d75fd536c3d8a64a2bd4a7e3e9a1691feaec5611580cc27076ce9a649fc10a4e247764313366530ede1e9d2e4a20581395773ccb1dd36163d03663b995cc243fcde5c65cd6c963c7dd6e49099b28e82022d15dc422df4ccb07a9d240f94740916f6f3b3faa0b3ea673914b3c1489b635d9f4ebac10eb50851e74cd4f928d267b08d2872e8a82817a27ad3d7c9155fc6673a928721ecc2b4b34732963495a2da4462028e6e2b4dd9116c2c605bf78b30eef494685063b5a8c600cb1a4e2a9614c8ce762941d50f1f4850001fdb508aa996a961d4849f17c81d1359ca849e06e09517c368e200f2ef480e7b"),
	}
	TestOperator2Proof4Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("cc11a20dcc77580f01fde44fa81141c02478edb8b0a97578c210516990c2f2cda8ac14f2b0f92fa8f4738a3e9de9d3059c0fb1b1533b764ae34252937d348983b0f2c258d241c7fd3289274df373a6e8a50531c8b5480df6e95ebea6365194673577cf37471908c32edbdf10b245b361efb0205fe1c9932228136f7ebf1256c671ac80fe34105f0554c7ea1dd82fd23e9c4775ecdc45a1321aa118df8a5ce6c1c89651a9284324970b9e0d2c3e5683ff27114354b5a8556eb980d837ec7f57ca43717d4d7266a80cf958edb14f3c22b2d0acbd6eb2592dce75f87123e120fe9ae049429c6f71dd7e9e79d2ab15574d91c5cc17540a66ec6bd7fe02b7ffc6e52c"),
	}
	TestOperator3Proof4Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("5b4cc0b469d2f89b44b87c63f5496d2b7d698fbcb7d39a184b9e6b987d39c4d18eaf1e16dc2753ac38babdc8b8bceb8d3114213c27d209f5cf5c7a2219453667a2a4c5a07d80ee815fd898ca44bfda93d87fd26bb786a3ab79bb1f7b8df5afa93528ba32a4bbff1a2990ce40803dda9c6817a8e54935db6bbdda3787955bf6242443e197b872e2ee5a53d295d72f5960b731ab42ffafa8241e798c983fb010acc58aadc973a54b7a33f163884990b8fe133f8b7ae5c3eea4968c9b94ead70cbe7ebc5d767e3d15c5bbadb0159e2d3e7167650b28fcde3f04ee12b35f3a33511a25ea88686c102ff04fb403a673960bb66870885a772ade0daee7cd82f699a896"),
	}
	TestOperator4Proof4Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("7423a0058c5d625f080020ad2722302d15c5cb4eff46158edb294beb91630bd1b3519bdedddd5e4b2d7d771210026486b950b490ed5721df69e17519ce1c6d707eb18fea700a84653729375f837d37156e344fd200e4c66d1dc8ef406db1a32e7d30b4662e298c70387a80b257ca1d6bd436ed12fceb4184f8743f322e8bdb1343e0f2e31fba4f01884f1500cedee30bf68345a4d7283b732db01b5db034d0f7152b73dcd471fd23c839984646c893a9459f348d668f77fd086d4c84f5a12b391d367ed60b81ef542b4faf2fb8f606b898474dc60dfa705d52ebc8a1919b0fa7b85977364be793e7e14f55b1a0e9b28682066dad0e47e0a33b345380c9c4eb48"),
	}
)

var (
	TestOperator1Proof7Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("453e82a1e8161b08742b61eebe074288e716abf6c4d6580356e61a831824bdf52f0f3e91645dd71b2cfdc813376d2a31b4bd082507248153edb1e383d0cd114fa68809888a32905a4827a13e772f54e8be7b968beaf1627a1fb15482adf43910f54d71b9a5c7ebaeb406f274f538211dc891e34652a9ba4dce82c97155d59d90566dc328fa5a51a2a9a1d3548d713dc92b9545e52c63e845b8234c0aacd13180a6917cf76127f5f73d9e53f88b73ef2df565a37b57a672cf80a633c33495244c242c37d7abe14d6e929c3d3af60b1e9e46e8419b8bca3dd172df451cf94137e70d7009987340582d78d1e717fe422e95a1847a36f24de817edff7229fb56e42f"),
	}
	TestOperator2Proof7Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("acdec0db809a7cfd38a511f1b81402a69c69c53d4fbbb15658606af3b182aaebfe38f2d44a41cbbd7fc0a6166d4b13af5a104dee9377c90a00a6f68788d52a4cce9a1e74394ce9818c5e78979178fedde0b0d91cbdfcc98927159f8ca5cf21bd263c771d77e2e0da5d61d737936b67e57ac8fc65d594d295ed38e0676aaa2e6e93bcd80928171b1c7952fcfa9716482912342dee75242c88fc2d5a3f23b631b7a25519d0eb8021eaacd3491e0944489c6984ddb0a4cabbc3cefdc557b9abb2567c121033a8d3e93527e7199416d45d7ed59add8af3fdd26639ae696c32db66f07405412014324003f2a580ac678aae18d66a0006b8afe181e296c05c4047ada0"),
	}
	TestOperator3Proof7Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("39a68ef4e49d18ef4d82b0f7b0bdfebfec048807de1662e5fbcc75d2aa5f684a6389c360023c5405b7cd4cf926dbddf6fdcde697657bc65d5b0236570aa29d70f07240fcc8fda7cbdcef7765785587e0dada752d636782ba854baeae78faa1e15f604aca886badcb99f40505be65e722bc5e4d9f36969c70dbd2479b779ee287415f70221823e0b5c434cc83d5c785f303d769f6c1bbfe0a02897479f52d21a2c772d773986e694b1a7d9579e78f9111879ea9bba4c05443c7889d7cd57c6d6c69586c57347b6fd5f09abef3a7dad95d22584daa35590dcc894020a8de95ec5756dfbe78d687120ac488e5759dfd4ac4cb07d8f8e426bb086e8828dbbabc34d5"),
	}
	TestOperator4Proof7Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("40d971d4e3a79c726f3a779f6d102fa2216b2ecd0094ec80d536acba304a0bbb6040f847d6db7b08e130d512d086ccb7b098cb763f4d1cfe472706e52d7332dfb5cc6a4b18d68681f495b434ef856adf6c94efbb2f83887d6358338eb371e7eadb3c05e0fd6194f9081f79c99d566693963cbfa1ab9a3e549b93017502bad0da8ceb0018620b2ef8d174341d08db45755f596755d827174cbd76ddadac66269c559611b6badc60bf2e6a2e13afa5f480ba4bf9b3f01a23c70d2433c653c36f926e9317753befb6dafaf82029e699b2862b38a85dd4eec1c457b7e526c30bdf2797cea7bab977eafb66f8fd7e55db687c5e6731c6fbf5f1d8d93457d813f6aaed"),
	}
	TestOperator5Proof7Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare5),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare5).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("64e1c1b752662bd6b5be1b457991ae9764a7471be6b1d653185562ac1cd499332f5d7b748f21cf5e61b57ef7ff48f65b4f3bae1736a1603689bbefb03684e3c4c3e2f992043db14dc0d49b48a27fae55fe2b1cf54b0c5a75d17849e8c706d473d557241a47a0644a3e832ed413ff3c269d238c77e364f98917d1ad45852c898b5debac7278494b85f59d3552d97bf11fa079d70c381b00637b49da9b29435b03bd1a23c88b6bc82c8133382954e519c55470b4110885f53ab94d3b9275b2f2f7b305db375bab2c007d31728b5e2e50e76d034a7c8da889541a742bfc9d01e9571210663179d0ead0f39f3b308b64f2702445c8e6018ea89c07371e58c30f9578"),
	}
	TestOperator6Proof7Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare6),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare6).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("96625b0c4cac15cbd8d7bc9a5606b088f2e530459b04b1eae87716f3978e2fee5e97d8e18a94f0dbb94ff8a1a4963d71f8721ad42b83773fb6b66163e267ae1aeff412a691a1395ec5b95b4d0fccc1f28ba2f5e653010dda4ebc4a9921553db9e9c77492a61391a8d5ef9f18f440b6c5ba4ab5f5250220f13dee210c8bdbb55ac59f47d5502cc9b4b2ea899a1b6c2679569e3381a03bc422f53c91220b6b5f5f8e421c3ef64db1044f73a8737ec4246c906650e3b5a23a717a1f003f895939c15f904acdb9877a892656300f0d73674908d20cc5d54c41985685612a9e6539ecabc4a70563f3e6ecee9ece2a0112397565ff6b75414eb2a63fefee07941ddec5"),
	}
	TestOperator7Proof7Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare7),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare7).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("899d6c1f4ef053f425c663307201fceb93bb4fa939d8817cd9e6c430ee927ee031ec5b54fffc67bd448ef7260f78b55f026f9457af0698a9b04f1e6bc4d8d590d8467f101e81736a6a25467d58bb4cdc7ff801e98e39ef4bcb3f5c1e1bdfaf0c9f3deb7f628a79707a99057eed5f9ead94c408001fca21c252da26d20447c730250ef9e1442640c33df154774d44aa6d1058c5f6022eb0e0c66f4f4a92ebc7adbb5239c8b3c3b4566a61e1520163675e1b89c9474c0a70d9506d7fc35b61703b009374bd396dfd72584442673b48818e327d523840a1589deee894e0ec681324c47e795f4f16ce0c25b7259b46201dae97041bad53b7ccde1a6d6d02e1f924cc"),
	}
)

var (
	TestOperator1Proof10Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("5f20f52a57290941dc1c65e3cb0a2341ff55248c61aee92a3b0ae159905bd5f4db517f54534567f0e2570b7ec3b2266549b13b74d15dd783ea33f6dbddf1fa8a2c25bb5a2b1fe415f8b51ca07c4795d34e5c39a9f37d82e25b823eb3458e80d7a01c427daf962aaca842bdb7a8d9c239b42d83c511984b380904f54f22091fc7d38d8774db9baff9ed64aaf9c10370c8841295a3f4b5b4d1ca517c5e618b4c085826a880b388325e3915654861303df8cbdca5b3f83e056ed0f3a944e27f72bfbc0b92d56f8a547ccf828ae9b9b430b37f7b945c6a49d6f04fa2ee6d84287f29380d790b4aee0838fa72111cab5b8c9771145dd1268e406adc4a80e8a955a2a6"),
	}
	TestOperator2Proof10Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("30fa17e4030c2b5f2d3fba0fd68cc0e93810387b51d88f911f3a03248839b2828c1bfe9da7f7315c27f6abfa9936c2d738fbea790828ba410b7f0b1a57aec04ad611bc448bc28618cdcf1579c0e49e45e350ecb73632cb81c903d9ea5a33a46b2aa5f6b8253d90bc32a873be35795b78b4bfaaa64ddc5b2440b66624ef56ad9c475d89fc86b8685d0ee21bbccd16136ef9a160d4913d9f297dd998fcf40121a2ad80df5b8c4460ca738dbaa8aa265b4febec96f474687935756cb1a693e3bb63b2d874f9951fa0cf40ebd2c0b3b3ea81ff5ce50c1fc99b7f5898de388e0c6707e02e02b1a89af5e6743950ff9201e97b90ee0c99b737ec6641da62b9fad57a94"),
	}
	TestOperator3Proof10Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("6a8e1961c86a18c84b2712a2eaa635252ac0c3a6b38d413e2cd2f144dd0dee045d660c91282c8b65bfba572f32d0dbea7422060d39b383c40cbfa54582c244e4c88610afcc958a0f085968f0a888f9d92cc57e28ebfc7fc8cdf679dc84bf2aefbf6e81a09a9b0da794fc620886434e2911da4dd23d9bc4b306b27e4518061126e2b0472dd03d238f55ee2a9e9009945832491e6fe105b23a54bc3bacb575fb745453e44b6bfb32afc3652124d0f0caa6b1a28fa3a2e8d7dd99da7039fd889d16693d3d088e3fa0185866668b7e86c026fab8c0527febc3dbdfbe1a91b0529d0ea6f36753c60a5ac1609c24d7fc286275d03ecd7c8530990efcf1f801cc56e87c"),
	}
	TestOperator4Proof10Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("6cdfb9ac33e50181ca229ae556d05f9a7ee0622f18b5031bef2e4d871ace0e9335d66e470d707d285609bce5d03cfef6005c1b103bd8ce0799a2f69a914d06c56ff6fcc63f921440f54d82c6c4d23648a7340beb5429d114e0826faebcae72ce8de566989e0135b5726b3efea7793210905af1bb196679dac1a2025fa3f787d5622473b6ad080bf42e5f0155ec9f1f35382b282ba88ac72066d75597582befdae3bc4c9995067a5e23fee2e10f68d2be7629aeadb58f1e3414cd7380d00f7a665aa90ddcae5bb1382cae100ecb3d6d22be6f39226c2883b8a1261c41d8aea61e7d4f2e44ed28829ea321d198b387c41f03f576d2cd9f63c24de08f81f2541667"),
	}
	TestOperator5Proof10Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare5),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare5).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("2e6b126d1908b6f30f7f70951ee928f9911ad5e0f475392f59078b6f8be229a1479f34efcc16b1234d79720f835b9eed284b182caeda98a9792da98a2c34b8a3cb2040f4ab4c90e46c1831d006432918f72e7f8b33a4b8d18f536690a3214497b6da0704db5157ca25154dd0b73eba0ce49e5c00f420e43e41a0fcc99beecdbc678efd214859dabbb06b1fe9316df653532914fd80f7c52ff7ea25799fc618c793ec2f091b4add760ce1307eb82132868acbafa345b6c8716fdce7fd0e1acb3cca28ca2d32d0530144803eb4db7bac7707ae796fb4f5b28d493c685047ca06075c54da9ff7ffcf1ea9d7f17ce4d305d3be6f828fa680392f6911c487fab0dba0"),
	}
	TestOperator6Proof10Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare6),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare6).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("18c9e724ff21bd6fda092f29cb8e2a87d636f3c6b189c074ecef31b8e18adf00c19bf540ce68f3a518c702aaed17e0b605618715e90c340d17672218f51cf1abfd8d44143e7a4a1928e7552b33dd12fe75a3b73c1530c0427c22053beb49d120dadc72aee21d7758f89cff61fc321b3579a55f268bf47dbbae1e9e9d9688517099b738f3535da8cff3fa2844e7bb280f657cb21176c4dbddcdf2e96bc31d7d72ce48eaf681f10dd5f5c1be7a6510e3290f8b4b61f768e44f79927df6df2c77dcef84f40641dcbeba0b2a1c47fa361dcb10524668997d0a9d9256e916824d78b59a3f49ded44dccfd91acde9a7670b2d8ccd45a36fd4534a343e3f9f15b16b13a"),
	}
	TestOperator7Proof10Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare7),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare7).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("92764a388ae92475e42b68832355956d47c0ed6748f4353a3ce973ad0516aef83caef328e66e7951f11383c738b2887978990ea18fff4ce165ca13f38bcda8a835da90f073a9713863badebbc2f0e39d28816f0ccb57475b0223ba1422acdd0293fa676b039666484c39457b0a991a5f7d130f76e6f278b42df61d5cf8323a15ab8f96047bd58f1d4f75e260dc89fdaeb87ae23a9ad96875dea7acc7562a6bdfc8a0599bfc662b73d011f138aa3061bfc787a7a2b44e2c74702bb4cf3dd91aecc84cd06736f394d6d564e8098576e013cfee970e249dbf6255455078bf87d105420f6bdc6c759b457d746c5769fc959f3328c5fe294689a7a571652ad831fac6"),
	}
	TestOperator8Proof10Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare8),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare8).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("8994a34c0699aa06bd26eff47319e1473eccc8034514405657ee3e56d82dc2cb0fe036c8cdbac610da61fe89717805c4d5acb66397abab14e65969b7bcaaaada2a8e3a14d83de24dd496bc9193d36d0fd68653ff453f63d58c677c4e2f62c7120c338f95086c410ae548df89b87d71bc794960fdf45f14341a89e4af176f4268127d55021fa0efe7fdfb71548ab3d165b86dd44bcc8a5971cb9ffadaa90aa55d94474b4fe9c1864519020a58b8a4c079163da3834edc1dbe6cd019ebda376e542299c4eeafea68083d730f0a8ad64b7bcaffcd7ca11bba546ed3de965ffbbbfec66b4e7d577a03edd174220783987debef37b631b568e779bd36f189cca82c00"),
	}
	TestOperator9Proof10Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare9),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare9).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("35d7ebfcfa01e7d9fd1c5263e374df5781e92a748b50af2bc2585b6db151b16051792590fa598059fbd55cac28106e4eb2b73107ff1b1d0c4fbd03fd68fc384c80df24b2e0aa60faab145b4358906b007c554481ccc3140e37252e4f8eb03bd6ef1f03f0bd68404625a9fdb109641c38c58bcd37a043c1fe353284a6726d964f2415b89e8a78d550f368aa9e3e282d791d2602fcaeca21b69601eecfff7cd162503769eff8ac1469259dfdff60079d040e5aa6dc40f25c43a4cb5c025a01aad5c399f1cf08581ccd3a8a0918a0fe53322ecff56589503f97c0d9c7f28ffb41c3a42773ea1e6bf9e01e8e5bfba1f70b1ac1599e5b804c6607793f63829dbe9bc0"),
	}
	TestOperator10Proof10Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare10),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare10).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("6b9d1df17d4d40276a3cc42c487508509f70c4b09cbf3bdcde6e936290172bf18f8585cc0d4cc9d1dfd563ec307e43455151470861807f2e37da80533c5db372d73a264d5ee75ee3cd65ecaa68e5716482de42b1b4f1950d46c5de18776c12cd8b1b836eb680ad02dcf2b54825a01dacc54dc6aadbc350019f5db042d3c7deead6ec078b154ceb4fe35cd0a1ce0a43b94d79b2c71027ca3eede836d8fcbba8136bff0039d3aa10b00f9941f7a0c72c00e5d8990a5d8b0d1039c8af01780b33b783f19692cfb245c2f8b3f27cecf382c36ce1e13243016606070c748c869a743f2b400e73deae92acd5e399dc1802f6cd7e1e962936233b798325c4f51127190f"),
	}
)

var (
	TestOperator1Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("2580c8776b210259ea739082889e5209b66c291561de4b8fe4aa5cd1dd3d4597fff20f097eb8d6a972d27329e2432314e2b40b0ded7b97ef881e878332926adb4d22265bb8ee0f1e35ad95f4895be9fd717cddfa9ab6dc44a9c10f2b95383b2d7dda890dc8704470a2bf3796a8037de1959dea0a1a990a9d99b7d4c1a83378c8431d04a59cf90e9b8e71be9f199c31ba6ca69bc6cae4feb2042a657fb6938b47873bbd5c298967334cbaddf26031c1c267bb01efe252e158b4281a95f5cdbd8008be9526afda942b12a6608dd6bd81eac0731598a47eaf69c6353c549e805ccc0da58fc90e6dcb60b70f8439f9557640592070d2e620ca35ecf604df868088bc"),
	}
	TestOperator2Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("2aa83bac632d39c144b765b2d5ca4054d8a0ff289a1ebb90e1d1762ac21a405a73514519a51c0a6bd1e2143331347a5a7d01edc9348dbe3b31d6d5b7a57f79567d41a8ef7d5c2fd9a2ae9064ca6f11ca07b753c801d3a97973f8317be1ae8604c2b7b06df70be70464955555db351152aa54b703bc5b93c476b5847a16b7678116d3d555ee72f74cb10b93c6fba1df0c34cf6893d20109cc6f767bff932e5f1ce94815df84e17ae8cab50995106b5a3167e5c83e7f4661395cf180205459c1fc22e4769408e1f15fa307963322cb0cf76a4ed6f2ee88798f3623c7a25416e9907261a2d8f5a753d7d4b62aaccad2c3acea0c7e046884a5c1ac64ad9446d478c8"),
	}
	TestOperator3Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("7ef278ce4b7919c2f433ea4c3b7cf730f30496aa55a8409af5c7140640d5dcdeb06bdf84cb29fc695cec37c34b89b3ac4391e4e4a133ae9cefa703feea0e654a20c945800527190f4d1e4fb738ea01c43f48564c859fbe3934dfceff44d8dbf0081b5ca654460d2b55b0f0d44eca2bb48950513bf030ededfa51134973244285eeb44b16bb7571671c958a140a066a3a6cb36e265f4eb1be09c6b8eaa66e3eb97a10bd46e15551d8e61a9989708f287c1135fd2b18984f045541d4befc203b04df26c186c77a51123c7879617584852e719bc181960edc2c5d1fd0b30e90da586dc29b2d7c6a0f7473a7580ef569e88ce55b440f5f0b2f971e930ea1d587dab5"),
	}
	TestOperator4Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("73c3d8775942799a266f773a277e89444b6b57d88223667496ffca9caa69c52f7e94e231d767ad3285b4ca8d023cc5f5f972ccf0c58ea7b7be624a110bac9658327d50b87c448c8ba92055794352ab10f87400c5273beed2173aa7f1cb83fc3b2864b8b4a62854a3c061a494a4e1693922d9998f38ee22e498c94ed1695e44444a3def697bd5e4669d12d49fb01d56e58746397d4eaa098e916af3ab3df0547f0cb6f5ad086d22851536c1feeda9c78eb90bb881355796950e405f5afaf1c1f9353023d85c87f8b50b1047bb62686045381ab301c415ef8107303e1ead16d2dbe8f691c815e2b9767826b69dad6a98df63c8d1077f09890b85190b898f194b3d"),
	}
	TestOperator5Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare5),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare5).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("43841f8dbfd688b55c36a53f8ab12e0677e2200eda03def6b5ee4f153651cb77debff7d744f097173eff666086d9e863f8db61d3203f9946eff36e94fffe6e4cc1d8e729e99d4cc96771e142f50f5d56d14e45e1fded1ce703761495ad36439dac249b9d2edb29f7c15bd3f1ae682bc86a4f00bbdc2a65adbf150497dd565ef0decf8470590e829a5d8eac97c4caa48bd54009b90daea4831259d320c778ed88275c0afbf675663e6525e3b9e2a0a475221426d7f519941668d5f747a333e460215d95c2291172a408a70e5a4ad83f242b1a56a2766863d95019910952eb14d41f5a3c9046a12a4f6a83382965c5a2cf7292a168feb389f2bf2963109aa38ce1"),
	}
	TestOperator6Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare6),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare6).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("719e27b5e341e55140de84ab5542fd3a3737e65307c0cbafef31f232638a915454eaef6977d40762913f7d1b48394e14d52186a6b35a6464663ed44077f25405f73503dbc7270dfdf0097fbdd210e8de5d27408b0349490541940ac42ac0f73444d8cbabd4df89855e1296878090a09381dba2088dff72174d731a4f0ae67b5450171b10966f78a6af2f396a4911ad44bb2585b41b4fb01ff00cbfc1857a0cb8d53fc161df11b5ccf6b2bcc3e7b8fcc6b17442f7c6d88cfe50be086fce1913addc9e4a418efab9829be85cd08e5d3450e23932f47ddedd60d0fd79b3998aeccb5fd8a0cf3540b4fb07de43c0d3e3f2afb00c58bd25a19cb4952375f1a57ea582"),
	}
	TestOperator7Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare7),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare7).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("17f22e1bdf9a47e96fd2e94558cfbe14cbbe5f28469925510e9c081c45be6de1290b4e36f3657a428eea6336c94ffd846541410451c74335014721b4a53ff36496eb823ab955cabbfa79537a9e24d7e4ae373e54fb2f6fff9776dce7ce94a86abc49b2bac4f90d498f21c8694268ecae82f882b838d289bf1137ac10ec656cdcea241e93847f6dab19a775982657df287067d3c0ea301cf8ff8c7e9ccf0fdb0e4dc2ee83b464748701a43000fd62c637b3c6ab50337b8f0b716117216cda9aa00542a56cc61563b1402a0a6ef974569638a957d2a5a8fb72cdaa640509e3ef01567b141db4d262c220292874d088b3208a6cf169344c4b4740b562768831467a"),
	}
	TestOperator8Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare8),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare8).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("4e2fc586b9b00a057d644030e8d168506893216e77077ea27f7732f718e5415f21b273c75aa2f0aa49637e3dae12f2e9d802ab98c763b182ba3edf50f4cda09b53a10c045a131b2a3cf2c38139a588cfd19ad88250203bb09d083b765b73ca5f118489ac389f3d953e3e46d026df1cccdc3ef9a3fbf6c707cb61f8316dcafd57f8c511b04f021f879c032e3f24622885fbd8db70f34da6e2bbf176c5510ed88553d175853c6b045133390f87c5f131bfd872e95b53bd3b6118ab2e7c903b9afc18ca6500e7889652979b92809cb797e92cc9bd580f7f766622f72342de6ca8da381e70d66b8b0aec0b2861df1b6666eb819b2ce2918b28fa16abf092b9360467"),
	}
	TestOperator9Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare9),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare9).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("34d421e91ee9238b5c11503c60e63f8f1ed6330c213b473bba655bcf480ff42236a6105aeec89db004cbc1645eb402c23f47caaaaf380f9f478aafa74d72a0d80120a1f93eb031eb60530bcfc15b85c7bce4dc1c1b462c4494d0a31e0ad9b4f1b8bcffadf35922044979eb0c667bc3901d8791da819cad4f15d74b2f802177c3fd3ba1f814ce35bd79bc047ec564d90fcd602901c8a89989aabf5f1974a6492df41b4083158046321280add5ceb13915d28dc24151b8aac2ca4be7977287f8a3bf4beaa5ba92f17c5cacf65a2afab849c3a73fdc61c2082974d8dde8ac1e30fa56747167e5c1399b13a314a24913d7af643b29898fa113aa95bb942ac3f214c2"),
	}
	TestOperator10Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare10),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare10).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("c73c866451225c9fc2b8de700b47c947d4c3783c517a7aee5a66b05696013c4c02b89f6ade787305b47a9723f328a45cc9e98f346aa56964a0bcc742ecea47101b6da3844c2786d819ba59443d84bde87e61d0fb04f10ef93dd84e88667239e654af60fe0168ecebc0b07d1421aa2db49aa8b9d288ba3486310745832b4476209479da8316d2e96cfbbb8d1aa9e7b4b3dd32ec28eb2c785b06f8775aa9e08ec2849ea882848d8e38654dee670d716184900013206369922e92b0c0ab8e6d818a2d2084e04e99dfbb8ce60393e3df8737d12e6cc3d0b16cce6c0ff3b8c322061b0d45749c75935adff3099f92453d4c76d2d06113adeb581df15f5eaa2a323293"),
	}
	TestOperator11Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare11),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare11).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("b0e2a83dbe95f0e2da4b8e193fbda124cd4ac20aed3f028af091caa04328720193eeaebab91c639b8e03819312765e194ad826cd75859d69c207356c13182e56b097efb6e8a32bd1c79813e8d6331be6fce6967be2bd0944960275e6e546842d14c1d0727368c839ed58b63568a93e2814ebdf460bc4055366b75b6eb2b502e1f8add0533f432c71bdfab24daff45ba4e2862d85baaef4abb568bdab40d2002d824292fd4f27214e5c42c87e0b31745556066be1882170314fb9abb4100529f86a90d51e49e04d62667c1913da249d03a875799cd24a06d85d5a1def133e6325ca51d39e0cf889ddfd132ef6eba0c455d2806683acfea193ed341d7ba757e12c"),
	}
	TestOperator12Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare12),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare12).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("77f074fa976bbbd46d6c66e0eec7bb1cba3ce94652c3831e232cf4d482cb153a8f55458c9ad078c9b124f9d744589c10599aeae12d4c8531e920fd435ed59a183b0fac2e78e571d46216bc4c646c08bbe555bbb40dfd2abc68578274c627c9231c7dae8b52a88d348ae2ac969d5aebc13f05297d8bc865173e1b97dff52937cab01bf40be965e68ec8ad050166f471d505b9991ff0ec21e66cc05abcc1c924f8d06da94b348bfa9b88db1564b58df51c9c70d53f6ef9326f071f0586411d9d009f2a81b097c89992b6a9e1c591a6fed057bc395bd16af2e6104934b2cda4fe078f0a271d367305f09daa513f97cf91fa6158df9b4393c6eb234d23c0ffce4253"),
	}
	TestOperator13Proof13Operators = wire.SignedProof{
		Proof: &wire.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare13),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare13).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("3b3ca95b386457c01593be5b4cb88b74da38121df895f8b134867d1b8e2e111e3f2cf261ce02c90f77e2afb468d80db63551a22c33ad249817e21856e7ea144b6359998c0d857680ea619101d382784ccf6a693337fa9a7600a797b909f14f46ac8a42153074468a51c443f37d3649f4382d6c3b515ce76530dcd63d67a79f37ffe99358aba5e30cf38cc4c30980d86610e635d98f956197bed562aaed013bb6eb62b91a85bac4dbdb111c302dbaf90617c6132f7a5cb82fa57e63db6ee661b0a4ba121d0ae4655f50428bbf8add72a7c3fda72853c4d263488f628cd2c3e73a2b1acc1802f70d5d1ed37a553c27d2c0fb96cb5455b3dc1d6f6213250bfa2f1a"),
	}
)
