package fixtures

import "github.com/bloxapp/ssv-dkg/spec"

var (
	TestOperator1Proof4Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("53f81fbdd1240146d6b9d32ebe90145354f7bf528e21455abaca97dfa120984544d0068ce06b8cea4893fe1ea9d99754aaefde2c94dcfb53458331747a5464e2eaa3397b1211cd0946fa3d2fa9157350597bb1a19e7fe3b6709f0c8728ce9a0e0cad269cdc84cbd5b77e8965649ce7286b7da3c6ba4c6e323f242af53a58c0094eb9e715fa9899ebffd2a44c12b86b149f4a08a1ceadbbaa8031980a75ee04f11767983308bf45d8a16120688d4406729380a0e45af6d183e43deb8736167175fb5060840f03057b3ca8114258f4dd42d809a05c41015d4e25be61daa20f28844872a2c8b04743193a4dc7f6bc61e9b8d0efd748651fd76839a2a9576c3644f4"),
	}
	TestOperator2Proof4Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("a4baf0fa5e1759e6bf6eff78cb69a1490d7f707b1eda653a71ff6c3cc9890dae3c9eda30999bdcfdaf9154acaf262a6690fbc24104933c0c0d30ca03cffb5fa1ba9b191ecef8c3912a1d482b7df99d737a82225ee2b519bceca5cab9cb83db92e5697bb0bfe9d0f24c9dd8d051240dc19f9c9a2aacbf0f97b99fccca0e33aa7005e7231a120bf6a8660d79fd92343ab4581c1184e3fd50ea40823196f5d4d0ab02fd4012f7b903c9abd1ac2c2b478c49de2463eba6a8837d7effea191fb7a42d112e93f051e2abeb60a8d9277ccad00ee72e9aafa7ef893cb5397c46cf2dbeedd82f933057c9df19bd0e2f659b5cca72aac2805f255673bb2c6530522b6a7d64"),
	}
	TestOperator3Proof4Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("8aad5bc23a85bd8b7e241d3b65cb6d29c27528d5bebb57f8b73decfcb52572153679a05739b5e42711d478d23e4e058556fead4d891a62bf4d8ffb082a92021b4f446ef876300017936aac46b3cf734fc963deedc49e46117d5d7ec6a95c4dc8df00b3af92971c7e9b5c443368887f536aae078493d2bb48dbdd52b13c2c4e85a1276836e0742f01707e40102702f6ded7c604d1e3f20d86a8aa2f983059477376cc22377bd661d60b786c7687d2203eef0af15a6c8fe0079565cb553ef0b89ca4b014d7100f3b56c3f875dec0fa7497ae77b7dbaae68a6b0b4a2bb53064d9d0ec28b1e2086aa11beb1355073a15e7ffb04aca5644ef7dc7c5f8addb0ed1bba4"),
	}
	TestOperator4Proof4Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator4OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("c1615a2ff332059035db2baed39fc3d970b5ae896f62aa7addadd5d4b1f186f7cd3aabe5b1f2d4f95ff0e962b463aa1b8f3af83f49b809e805c2b42c12c79d66ecd540b64391fc48bd43cb1bfa10b47ff33f625b26fe060cfb116b80b1c1543602f26c576d1a23f1d7b7a566ac04dac794e9366bcc0bc91dddc7523604042644f99b35423e7f133dd07231d5c11e6684f0b429a6e9de3188ad05984eef4584bd8a2cb40d96539fcba87420cd013fc0d2cdb5d1e57df6b54ef03bdc8def1e7b33d52b47dc13e8562a890e761eaa6977903d29ab9b2833eae5f64c0df6411cda154f11e8a05aa48ad34a5f7ca2536c8c25daaf2fca7f08795f474d49cff065638e"),
	}
)

var (
	TestOperator1Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("aa05e51db4e8f130037843247ff0495c38c8f30054a5fd19ed47cb83be8cf4f81aa1d0fd6941033f5764294d67354b8bd6a950b70236a008f9412a2265589af46c1dbfcdf2ec38c74e129503f5ec3c587b389ef82c77ff24b28f125e4a134b91b38aa6db87c4a5a52680cdfe2e980e3ff925bfd5fc87ba51bdbe78daa6706bd4404a1fd2cea96756a4a0d7c97c1af4018cecf669f3aea14dac6f72f49787646b147b84cb0694f031ab0095d41f830bc2786d5e1c9e7f021519218e60d37ba048cc9a0f6e35a407df0ef8204aa41c69de8a81ec4b6b23dbdc93c663a5d7028794814a7387d9efcfdaf072e9102a662151c2bde2b5541f1192817d1519d1949566"),
	}
	TestOperator2Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("209f900587526ef934558191cd4a6a949c8985709ceb8bdc2aeccc8319d752ea1ba3eb59a3364b8290e7b3289027417be2b67af6d363e24df00119080a98af7222d4fbb94e219bf72910cfbf9da64914948329ae639c4cd0842c5917618b62de4c9250a8eb84c7b334e52c0cf06e4f7325d59c46f305aeffd2cfd433fcf91756b3069b7c919a21b331011e7192dfc2f7acc30a79ef25ca50ffe91210e0af5c7741cbef99f0e62d3769db89c2a0c51a394d698d1c833dc45a7232d7b20df9fa9d8b1f245e9aed9fb66ee5aadad13c93a0f6b30369fed0bc1ac95b653cb495aa33a4406f8525fcbaecd9c8cf98fd42f775c9754d84c9d2721a114d9885e1b69571"),
	}
	TestOperator3Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("93c8bc04fd0ae686c7d55eb632314e1bc4bfcd4a3f6d6594dc9c4e0b620ecfe75e2f21210d0ea92c2acd77211637feb0dc3cf7b6282903beb5970e6e5f87fba86a737bb91a1e1a99627dee9ab122e2bc8f3e9ed6df94bf4edb4830ce0110c0367371b28bd3243e2d54dd8ddd33d44ddf671c38b6c9c8919e4b772ed5b21bb67e04b9511b9cbf5579214c676090f4a0241a8fe224a535032ea9a84279d1326bc5abb0c0e2efee74e63faac0cc7c986ad7d5617d51716aa19982c090ae2a42dd6bbea903b1007590a8c5f7d6f07388cf260c34642e9b90603537f601e851bd38de0032a9c8c581628afbb0995004c3a79a24671de717ad5239690d0c69fef648dd"),
	}
	TestOperator4Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("adb3f235494c75d5e8c3dc3aa839a1ea46e8720dcb75089528fbfd5910d939e05cd3a8be742aaeb40ccd7872d6d1f69bf89a64f9427bfd45b45455b7a2f285931f571c7cd4950b08eedafdaf28505cf5980b9fe365dd35edd805e9619d37a65e9f0af83f846938a3769fabbd9e6423f2f407d8f56327de47779c93b0ea5cc81dee8988cf8cd283fb24affe7db0c5f10d9696da4b042c2cbdd7f9bef30e80325a4b55edda75a9d64e4498d8639aaf4137a6211b6f8a93406a7232819927ea0f53a1f338eb976c40303d6d08e8597afad430893df7074abe8c9368ca9f855c867f139d0b46f55d4fd930be3ca145dfec5acc3ef010e30d1eaba390284f21e1b287"),
	}
	TestOperator5Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare5),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare5).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("5409adb7d6972c39c94b291c9a97a071f40f87c7d81b858ddf569e755c8dae7511380773bc6b36e128fe24d268bf153371584f15edb61f16ceb6a53c7b55736dcc7bb27660386342c8648dfff9076e4d7749493af1bd5b5fa0f567dacfb9ca4cbe8ecff4cc50c96e278425d71e795411a8a35142b23801e5142dc2539a5a0fb7fe1537e2e3c63f5ef356c5ba27e35073ad5fd400a4bbbab3e0f83a967d95d580ed391c372dc1e1b34097c2ffe7924c8ae70da5109488894d3041ed3c8f065884233b84008069e6152a89d95bb49a42f4d40f61709654c1d8662dd6e6e7c38ecbc9aa1143f52fcebe001d7bb182fab4a43982b0ecb8dfff0a3c64a41060e772c0"),
	}
	TestOperator6Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare6),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare6).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("8386a9cf1d4f5fb843398e8b6666dba681399d3a5e127a9b2e383ce74385da5eae2976b51d48af57e7bbc4bb3ddf296c991153971f25f9a6845b222c9be3d2b8c44825cf5d0e9d0b11a48e429e4ccffcbfa319cff36b53f974ad8ebb455c81c50a1c29112caa4977edcdca4d55b7918f3fe05f14072c65cc67851ea427e36bdfe26621bf248f7ee73c5e460ad32a72c851a55bbce466a0ee03d121866cd3c5183906acd632b1503944d725c96d7d413190443affe7357a41a51d53322b1a7be9e849e3b89cd7f3484554289ece145826c5d9785095a3c2f90fe6be02d72a1bde0a20d8ae3c90c20dcf43caf75d2c48c2c6d834714b65545c87d78e434e8ae3df"),
	}
	TestOperator7Proof7Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator7OperatorsEncShare7),
			SharePubKey:     ShareSK(TestValidator7OperatorsShare7).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("cedb8791bd457680bb9c0f1dfa5b4526d07199e090736ae82db4b6a0809b0b723a1655b6c84e765e0249746c4fd5a64b6698d3fb73819c9aa784208d35effae6e38e7a012e937bdf456e862b427e94fe9f233f6c37699c2e1b88c92873ec2b808254dd9501a7b7df3c5d0a0757cc3f0f6b96c9d78c00fdd3bf0314688ededea0f78dc512dcaf7a4c8c37236740dc635950ff14fb80186e03d06d32622051b44102d0665d684f8b67f0a21b6a6dbf51edbe9a6648c57e2af396b7dc97c2badc23b0c50ce30d38618b9a1cc31c7ae254c951de2154e5373a9030da9f8d70d3906bdc6e0144917bbf26f1af761df848787e795a89d34d2586d7710e594f1ef2b996"),
	}
)

var (
	TestOperator1Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("2dc181d957eba48a79c3e71a5cad5be1517f2154bde3f377601a0a13038fe29cab6c1c4f8235a8ea6f09ac3fd417a54440f2a45f3afebc28c7306fdefd882bcf96f004cfdab7b71dcc8a4db3485e0e38f1fc2e0292b212525a94bc33da0cf8f52abcd73bc1fc989e1d65ae24eb9eb47280dce9d879d91d850ccab20e068d4b2e40b0e8f6cb27676bd64974ed2d3b2b2a54012997b4485d27277b7fdcce1cf14ae71dde4b26ac033976deecf433f56f7e24c46cb3cd57696930f43e1c51cf393793c26de3391611613a426f6f700c73230672b562e608306c639a0f5c655777b5f7f10d0d82733593b0ad7f298f0143c8357af529fa5bc031ab0dba26de82d7ac"),
	}
	TestOperator2Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("491da79c178f20b911264279d662f62562a2bc932986228ce5b8e7a00bfd5db6a81b0c7cca706cd6ed3a83f1000bcba05c0302a7d7dbff6f9fd65e956921432a6eef49baf86b6798f5e999ed554707ad9364d7483024b0ea006b859729057f293de91f1da50db9b6fb44b9b757c856e33988acaa0fc8ed79ff7391c6b3fa58a768ffa498e3879c338ecdd12789accc666cc29b3fdc0f88d9348b10832f20f518123432deb6b74179a7ee12d1f46fed14123b9e95b152d92d566262a5a46539af1ac14d6d57b64481fb0754fef3fc31c82d0931c0e5718a3547d628774a55d6ad0b4a149b1dfbfe63c28e14bf1e2cf450929d5c03636b8abab5f469f0ec920a97"),
	}
	TestOperator3Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("3ffd039cb91b943b6fbbf0962bbb3cbfcd839241de586ea2b320c08d7b0d10e7db4bf7239919df260ea4d84c2a1199a072b4fc1be7f5f7b5947f72440e04f605bd9f00518643c786581b3d6d900b3b160a325cd6681d29fe207f5d6672f22e45f35805eb5a0058685bc5f84cbdc3cb5bcdf2cda37e9247c6177abfb9b34b4fcc59c7d4d94b19ac4762ef84298b9697d1eab18138cb9299c9d2d832c9d1f8926a9a4068e68d9a900ab3cee41beafc51e023e5c43e2f9710c43880dfade388534e09fd1483dbfb9118431485aa7c1bff7fb5845a3f653155fa356679a359285e6a6d1215cb2567866bde9b48f6d85f39de26273997f098a41f13aa67706bb28971"),
	}
	TestOperator4Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("9e68ec19c6b895598be287c7fe9a843faac8ee91710d6756e3aa0bd160d33ca9b3dd8bf5508217ac3d553ad5d39168e1362b8db263b56a6be8f797b7aa3ee63b1eebe1df17f8acaf0ee97edab90d1c307cccde1e89116d1e2ceb660ba23cce4237233f384a62242726a3eceb0307937561bb1ec605fce02c2005932ceff4776a304d24518e582cbcba3f8a6af5ef33a5efea0548861664f40e7d4d963c8ee364b00cfb683ae2e877872fbbb15199eb11ccb11a59c6597e1262eb9c94ac9c621765b8fbcf49a40107eb55dd37fd403236b5733d3647c9d1d3fe308883323ea90efbf528be6695fd1d90fda34edbbb252b4f827243474824e825dfcd52994b192f"),
	}
	TestOperator5Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare5),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare5).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("1cf74d8af86aee4f3de8797dc99fb3aff3e73ff6be7560a83f66ae953e537207b7d1d36e41cf2fd492dc840b2c63f0ce2dc92322520ade21753b16bb2a9698e91136425f1af0ce218079bc9b747a92c0e7931b54394d2875b8f226bb80cc1e798e6b850228bc85059f954847c357ce53a27d52df20548ef96bae63b07e013989a03335287e39ca1e58398fd368cfc72f35d7efe256153584bf10a3a39939027b538303b24808e3360ea82f8b16159110277deee6c7801390f29647b8c58553bb89cece61d5c46e5b584f660b003eb44388270df653b1503d20ecaee734638e697b03bd3a071ba799eac9d29fbf9cc7f6e8b4dfeadcbcb463aa28d3e2bb362cde"),
	}
	TestOperator6Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare6),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare6).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("2a1760d2a9f247a598ba5fb8194dbb4e1d7961a786ef254c17fe11f4a2c3b96af8548ee99ed214cf7bd4074c6e9afbaab3814b4c15127f52f31460bb403283a025429e6f730c6033ae5b04e240b5a97104e5144ac329901c80f90777d892f5623a63c0badd3590c418f0b4a444d4aa9547195453ec37873ec4256c07aef0f825b7ec2b9918b9c36889c28eb01ee82437c7cdf28083c696fc228e5b00433a5cb7f94307684585ef9e03dd4c4a23874a1f98449d7804d0ec378f610ea717e744033c1fddaaaa60f7b103445efd2fc4312d96633c8c6ca9ab27c59293be2aa09d47fdc50e473fdb74513997a79b9117ecc71e19756414e544a75b74d1da81006b0d"),
	}
	TestOperator7Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare7),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare7).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("2c323e687486adc56f94207e5b8c72493712ad60dfa1a55d50b9142d8722b779257b3344ca55729013b9d4db6983518b91a40625fe18b6c434f71c6a97bef3df3e5b902c144f697f39f7521578b8f25875fe67f66e5f6e937e26fcddbf8fb908fda12cdfb899b65d4487e8f6215f40d01438dda375c9dfb191e5ea61fe5a59c0f3f884bfddbb87b6b451aa07be2eda2cdd7c8b92a851a89e43a84885893b02ecfae2b7129917dd63f1db0cea3749353dad87c74fe22f8a69b24b421b1b168103baac67bf2be96d7bd086632bd466edd21987c18309619c3df15985d298c49db18a4544aec2ce326261338164123578ab3ac26150d3cea8d298cc41dbc1851d92"),
	}
	TestOperator8Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare8),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare8).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("249b9ac09ede6d456c4dbb5e509c4d289f56a92e7feb23ec86108d05b3f4563ae6a1fea79907829366013ecaff1bdab8f3d2ace7e1d21da41983ffea4da8df1c68d2ec5f3ab5075cbf344393726bc27125132ad43874d714fc0d78eb3fefe85127660bebf32e400c7705240eae7b7ffdd8728b8e30411e042e970f010be85f087e89d5b3830c413606e080f90500432c1b02bcc64b32fb8e37224623ced9cc62a952b8bb985213e505abef8b5d716372a647adf6ba2ce90bcb537241ddf93006986f771bd915a456e6d338f2b42b1f03d19b3dc16ce3b0c0c07834db167b1bade342a93627c372a071df3319e0aa3e9578f55d37329362aacfea0097c69e90ec"),
	}
	TestOperator9Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare9),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare9).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("6c5a8e69ac201928d5a9c71cd651012448a279ee65ed8c2b6ae9ab5baefdd93cb28e04188f3e2b160c57694ab60f13e0efc6c08c4b117ff72222767f03660854e79b8976226615862ffc87da4d58ab573decd556dc727a9f8edb153847e612c5bb856a007e1f549df5192aeefa018467acd70ec578683e1e39f954fb7d10b1adcbe500aff13ec0203c41ed42d7aae168eee9c6eac620c3303dcb5ab08f79f2130a5737ca3ef6355afe8b69d80fe3ada7e7908f4540a33bfe86a013d9cfbcb55fe9c7df361f0e2c161996889f3ae26275b1794afbe447eb0750aacaf06cb09c09344b74b4ac0140a930712c549d680224a43250bbc241a4227541aad7a036c136"),
	}
	TestOperator10Proof10Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsEncShare10),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare10).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("ca3b6e47f23313700903d6f203ebd5a322ebb7e180f67c61257217ca1bd92a495ead376d2c742fde9cd1d4a18fd351093c693a1c93ecb7c9f5d215e1541b418fcfcc65e9bc5026b8aa2c554dd10841f7a8c89cf9577c2131fb0377e896e822c1cec88d6e878d5828f77daca458085ca794b27082df0cd434fa3183cab2ee6eddd5ad7e95629e9bf4b2df243f196162ce3473d7915af081ce7f2f70054072c0c9b6288f08786f2d5e1610233d248a6933bd15540f9017be93dff3d8d29b174c04373895c830969a14fc122f87ef503b934f8fdb0643f4e6994ba5261abb205d803ddc359098976a90c5e4f8958a03203a907fd8688d32db0d992ffec955354c28"),
	}
)

var (
	TestOperator1Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare1),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("86d4173ee5714fd8a4450bd9c5a7779d24e8a5198b28b5bcbfd0762269ea4f56384636361bae888b14859b8d676e98945898c00b8758565bdddfe720095ac09627a85204596c418cb0c341f7454e9e5e5c45dbfa48539c7a3bbba9152a04eec8cbd9e72d4b7c6ed2d0f813c17c72c8eae8d9d381120c700359cf2bdbf1fd7d3e362bca32643ec614d04aea3ffb28fc82384ef9c8f46fa42c2cec7758ea19981e7d9e6ad02eb2470f7bacf8b7df5d075dbabdef02ffd04aa67a0bb04d7b05cc6a786b7bb6843bcaf2c6e76f82e279e6f2ac38d8ce3ebe0fdc64a2249073014f524a7110c38af523247078fffd10c89dce2eca4699f89b74cab0a02ed0cadec3dc"),
	}
	TestOperator2Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare2),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare2).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("15b358862adc5b7cdc0fae8b975d59d17fb35d8f3822ddc1821ba8578efc6de8663a82d5fe13b5c98c67981dbe917e664936b8d47812569c9f678f7799e2cdd030f55b6a0d3a527fdb3af01ed013fcf0adb4fd5fc13fc29f6057c851e1764dbd8cd3525b25a1efced96f91cfaae924446b2d3aeed464812badbbab134a5e67e523e94db35a00299be4114dac41d3e3c1494679b6998f761c9eb54187260a93d8e1425c8e728f9ea82df51ff30c91dd10e3903edce18f91473034246bb6d787a39357255068505d2dd112957c9b7d77bb88ca8f8fc792880dc5535861ba604451e12bf9aa8b29530e0e3b2173596f8a11ff738c6543c5c94594b1a383edef72e0"),
	}
	TestOperator3Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare3),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare3).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("3de2b06c545f664e31e27fe08e0e9c4229b68557637ecbdac6570c160e692b56f33ea763df902ba88e5eaabbfa1a32b2380f9229d5de1c28e997f745c7e1f573ac30969046e9fbdc4349ff4aa414f743c638f999861aef58539b22c4f79aba1c12fdd0f9b78bf466f07ef50cd99f2dd5141f1b6b297b1570e25fab7f3fbbb41d6f015352d06580f9eab1a3d2de3b6841cbd7a8e8a055ba1488523741f44ecf616f808e798ef43301cdce6c7eaeac34cb3bac01fc077c7788015dd99b8a8a19f89fe9b296ba2011492c31af8094c75808b97eb33f2f2e0068c76098e853ba6c1f26a39c30dcc8b7f640d22e04f09a28cc5ac3fcaa58af7596e13607400a5cfb08"),
	}
	TestOperator4Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare4),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare4).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("ad9c7fbcb60b2b6a3e563c3fcf61f1f8b35ef51b34dddf40d4c614a3300d3dfe8f1145661c345fb459023dcfef91f9b096e6044a5bdad374b4203f4a2cac240c9ee5083321f96382bb935afa11183ff21f4e00f9238efa4124950a5a22444361b97ce7a887f092dd6ac421cd66b742a1a34c7f244d45fa80bf864e23604d42f6c5086b89a199b8e14b9b22349d3b8c40f9129d28e826fe168231bdf3166d9259f895708ad2eb52a8e33d90d1588458d530e377655c686b5326a5b64dd97f45791e19a9cb409118b33147d0ec38f4fbe6d51ff46fbb9741a86bb8e25bf4a43a0bd82357b2ebcd69c844cd3e1fb495018fd7885b889c7c9a80e67684bea4d22c4b"),
	}
	TestOperator5Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare5),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare5).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("9545532cd17186f51d0d84eab60874ae902654561fdf61a0d28bfc79ded38c932e0aaaff51fb8081e481122629ff42af3df78bf57aa73ae3d9dee1bfb5a7775aacc70eca177bca29e7462ace5cdb253e1bc1b6829b07f289d5befe882e1c06cd3c04622db5a9ef4b483758c106e745e807d0cf16d03cc0cc341e84e6c023d572cf2f0ea6a5b40b0c7bafc8f4c6af923e3944facf5b7e9d1bc35245f0d3403de8963fc46934458176202e13250ad7f6bfe732a99d062a20d5f565fd7fd31d7bd945b862a97249873da96bd9a04ca86504d1418da954cc64d99eb3f851c50ca9d7d9e13bdc35ee898b12db5f9b177d90debba946f57f348489dd278a8a5d71c8f4"),
	}
	TestOperator6Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare6),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare6).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("39d6e95012d71f5b6a2ffb8019bbf20213db0248c75a9ee28667994ec82cb845b4a68980c9c70b55eeac02c59928ad66efe42ca97668f32e8294af195fadf2e9706a515c426a03d8b81f9ee5a8703f0f4474a3cb6bc8d5674af6529bfabcf747bf89ca299bb3e063ef7e21cb8f13b99c50a3827842e1193853a27e6edd3b84b928cb493ce2c6db30b37cad77f4db28778286747e85fb4da2e02e0eaf4b65388f3b8f7e4e50560d28019de1d0a1b7d266e03bdeb68ce5c1077862619f3fa1541c9f32bbeefc6a284e10eacb6deea27c1656509f64dea8321cd6a6c1513569af5b7f092f3f3f1d132ace416906b29afd0cadda3e47932ccf57d88860f9dfd7a9d1"),
	}
	TestOperator7Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare7),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare7).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("be1fe662149e615964e01a4ae726cf0876542d3dcfb4bf8305fbedd84d350328e06d8788c00163af19e1028eaec576622d55bf2bad4afe13e1d8bcca3287a41a41fd75c3f2a7980bb0a6c021b2560ecb1a9950143a967d26dae18d99f728d5ed4c31c5aebdb0a47391fbf1f3a28687845f99c179f409071ca2eec5c61e7dafa79aa53e1d6bc9bb49b8d2f22d3d9ebd881c826d70850d6427b50dbb50f797f8804d07b91ce8cc481967bf918ef0858be7fbd72834b9cdb4ae56c1331140e427459da58bd41cbaffed7229b41388555dd82bd5d99e9db4e650ae940c3aa926ef99852c989a8bea604ddd2278d901e5c72ce268df12fe3ada70be40fef1c6781f37"),
	}
	TestOperator8Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare8),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare8).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("b6c2a0e794ed3abf2f145e5cd22b0c9a7002fa37176a99938898abda4ddfeb21be709fa8d6babe2760dc69c0e4a7d73654b41525aef707e22c21c61fea32957ac0c849ad541960178056aca74807bb3f5b6337035bd9abbed93e22ebcc0e476e139c28a0e42853a73a67ac670e064edb0cce32388a3e8daaedc2699a03e7aacf9c2f7f42efd01ef9702663bb129992ae6d209f63a0929408b4df57dcb4644deb5bc34123ef81346a8e1db4c602f719945c670c7e76606a73367e3d20a834c293be39735b3cc4a6fcf5646006f0665eb671be6b684eade46ebedf4b51b70373279b3347b4114258e92cd381322fc100bcff0b5c3fe353633c291e2848ce168144"),
	}
	TestOperator9Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare9),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare9).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("9bc15c753a9b53bce693d066e52d6c5efdba85193bdb925be840e4296e68d0db4d55763309bd0807df086a6b5be7f1220b77e2622633419c6b1ffafc54cd2a71f25c32e11882866d9a49003dce342806033ada5587c4da833acc1ba2315f1e54b754421ef2b1584826dc8d5b1e3857c04399fb9b1474a44dd1ec0fbecdbaadac8c8806b69d00fe5ff2957f8296b202c78e48d89349a580b726e01f6c15578ec7b4b9f29cab52f14393c2634cc12ac20378e73dff24f7f41e5f9f0c4c5631f861c0d4d4cb18f7f6a1ce460fcfbd446ef0de132b47ac609cba171737736c27332a6f8e7944bdfa2596710c9ba5c1215e1dfcaf172b035c61d0a9ed5af7d75876e6"),
	}
	TestOperator10Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare10),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare10).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("3272daee0b8cab333474e1ef94883a9e606aa1e281c725b5a4543c63bddcb6175cf712fed851640bbe95f511e9201b8e87078e44ddabe735182064350d7751ce05a50638924684f6406e1748fa9735d29d30447e40c13c787484d9c2255bb131b57c9009b246ae6e966af7df6bf1b7c6e04fb9ff1b0591397bb8965b8ca6987d56320668728291116f469f66f9e0fac5790ebd2f0f5c4a3ee2395d240e6843aec03531129c21fc9ab289565201a65a84ca00a43bfe141dc43253505522354fb534ac5791aae6a4a83cb406ace745d597a576bc86ac3bb24ac85faa637233139112faa9c2caae0e54b7ce1dbb6fe1aaaf805d3c34ea1426a0d2210b686a556bbd"),
	}
	TestOperator11Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare11),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare11).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("2b7883f2c20daa80d5969fff2013a52214a8f44ff50a588fa5ad14198c4392e299a5fe7bf0d2c840d2709a764a3c788d275442e58eabe791686c6841c22d6b0c41da5e9091ed60770b3e9c988c31c2e01b9011fa82b2a589347ac992566e840ab9da486d09e7c7b5f1ae0d68769123a502fdc7cd57f6968cea321d103a0eca3e7638ab5aae9b7dc9ce8f478f527b068371961173b48fa93605b61bb79c7cbb54482a2b72b3b882ceb565d1fe2440fcf1711a9351d91730d8bf0e8bb3002b406992a42d271da495472bbdbe4070c5d4c99acd389681f1e5f565cabd102f577cd9151976f287932d3ea69a5b5ff96cc3e3d58d2f7810b7c62f02ec35434c719fdc"),
	}
	TestOperator12Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare12),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare12).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("79393266993304da6f5e90176191c5b446613c603a32adbd0c3dee6b68ee7dbb085fe9a85ceff05456be827c87650c7cbb0e7f260b315ddc81fb4f3dca727f2d1e9a296c055754ac2c2da7392fe7478f7f3c3eace4b68b98d36e3cb476e00f3e46e58b23c5f55a2eb91ff754a5ea9eda5b4d31409e44a66ebbae13f601fd60199364ac7c44b3fb0e23a08ef062e224351c12ae68e585c546909b875cfaa0ee661943eff03ff4f37a144bda5fa1768232ed630a005f93a27eb3c858106244e51b625f893c5a842c8e52c216e51612c6e1b57f45edfecd646945445b706f24cd54dc4f9be9a89b38518ddf39a6f74408fd347d41e7dd3e2b000d1165bf5288a053"),
	}
	TestOperator13Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare13),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare13).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("a9aa067e29f6b17f3d35d532e52c7aafb2a21f2835536a62968f6308cb4d9af117530f6dfbdd7fd95170470613f03cdfb47c680e2b8bbc313677c7f741f244a687d9d4e011e883bc9c88a9ad63423ca79160abe289f50b101843a479abf5ef5ffdc00f20575b23aa1324fc1b6f48be51eb2aa4bf26be0a0c841a937357f18c3cb8cb9f48e112c6cf4170aec341d71f9db32b5129b97a6be33335f94b299f765d828222eb7613f4730b9afc4444fe652eda7330c700639a90859f18097c21680ff114de930a15372c9929f4501e2028369e516c818aae92539324aeea24214a080def5b952bd3f9243a00efe44d0092f9f1299d135fedb4d28502ed67be416964"),
	}
)
