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
			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsShare1),
			SharePubKey:     ShareSK(TestValidator10OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("5f375203a0b36868088707a589e250961e6e21ab8ecd68171287bf0fa11514b64401f3f0565fe1539bf98c741e363668ba2f2fd2b07ff091f9995d075ec05081ecf5c68e37f3a5eb2cc4d2c8cd0592932bbcfbdb2d18b29455d3d08203fb683585ec7acf9acf17c299a6b86fe6110e96f91aea8ccceddc4c247e9e0ab37a5d016904457822212f7353461b50f56cb6e9afbdb089203f2f242ceb6241a03dd4865e020a93a6a261d9ee39ebd9a5f79d9f90d14a1d9d671b1ead744228e056155de6c66c56b08364b1d8706f1cc1b3b664c288500af3cdc650ac7c607b6434218136d16ac5c3c75923328481f9288a53b393533d8404a27efe0a8c6f6a9933c488"),
	}
	//	TestOperator2Proof10Operators = spec.SignedProof{
	//		Proof: &spec.Proof{
	//			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
	//			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsShare2),
	//			SharePubKey:     ShareSK(TestValidator10OperatorsShare2).GetPublicKey().Serialize(),
	//			Owner:           TestOwnerAddress,
	//		},
	//		Signature: DecodeHexNoError("5f375203a0b36868088707a589e250961e6e21ab8ecd68171287bf0fa11514b64401f3f0565fe1539bf98c741e363668ba2f2fd2b07ff091f9995d075ec05081ecf5c68e37f3a5eb2cc4d2c8cd0592932bbcfbdb2d18b29455d3d08203fb683585ec7acf9acf17c299a6b86fe6110e96f91aea8ccceddc4c247e9e0ab37a5d016904457822212f7353461b50f56cb6e9afbdb089203f2f242ceb6241a03dd4865e020a93a6a261d9ee39ebd9a5f79d9f90d14a1d9d671b1ead744228e056155de6c66c56b08364b1d8706f1cc1b3b664c288500af3cdc650ac7c607b6434218136d16ac5c3c75923328481f9288a53b393533d8404a27efe0a8c6f6a9933c488"),
	//	}
	//	TestOperator3Proof10Operators = spec.SignedProof{
	//		Proof: &spec.Proof{
	//			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
	//			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsShare3),
	//			SharePubKey:     ShareSK(TestValidator10OperatorsShare3).GetPublicKey().Serialize(),
	//			Owner:           TestOwnerAddress,
	//		},
	//		Signature: DecodeHexNoError("5f375203a0b36868088707a589e250961e6e21ab8ecd68171287bf0fa11514b64401f3f0565fe1539bf98c741e363668ba2f2fd2b07ff091f9995d075ec05081ecf5c68e37f3a5eb2cc4d2c8cd0592932bbcfbdb2d18b29455d3d08203fb683585ec7acf9acf17c299a6b86fe6110e96f91aea8ccceddc4c247e9e0ab37a5d016904457822212f7353461b50f56cb6e9afbdb089203f2f242ceb6241a03dd4865e020a93a6a261d9ee39ebd9a5f79d9f90d14a1d9d671b1ead744228e056155de6c66c56b08364b1d8706f1cc1b3b664c288500af3cdc650ac7c607b6434218136d16ac5c3c75923328481f9288a53b393533d8404a27efe0a8c6f6a9933c488"),
	//	}
	//	TestOperator4Proof10Operators = spec.SignedProof{
	//		Proof: &spec.Proof{
	//			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
	//			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsShare4),
	//			SharePubKey:     ShareSK(TestValidator10OperatorsShare4).GetPublicKey().Serialize(),
	//			Owner:           TestOwnerAddress,
	//		},
	//		Signature: DecodeHexNoError("5f375203a0b36868088707a589e250961e6e21ab8ecd68171287bf0fa11514b64401f3f0565fe1539bf98c741e363668ba2f2fd2b07ff091f9995d075ec05081ecf5c68e37f3a5eb2cc4d2c8cd0592932bbcfbdb2d18b29455d3d08203fb683585ec7acf9acf17c299a6b86fe6110e96f91aea8ccceddc4c247e9e0ab37a5d016904457822212f7353461b50f56cb6e9afbdb089203f2f242ceb6241a03dd4865e020a93a6a261d9ee39ebd9a5f79d9f90d14a1d9d671b1ead744228e056155de6c66c56b08364b1d8706f1cc1b3b664c288500af3cdc650ac7c607b6434218136d16ac5c3c75923328481f9288a53b393533d8404a27efe0a8c6f6a9933c488"),
	//	}
	//	TestOperator5Proof10Operators = spec.SignedProof{
	//		Proof: &spec.Proof{
	//			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
	//			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsShare5),
	//			SharePubKey:     ShareSK(TestValidator10OperatorsShare5).GetPublicKey().Serialize(),
	//			Owner:           TestOwnerAddress,
	//		},
	//		Signature: DecodeHexNoError("5f375203a0b36868088707a589e250961e6e21ab8ecd68171287bf0fa11514b64401f3f0565fe1539bf98c741e363668ba2f2fd2b07ff091f9995d075ec05081ecf5c68e37f3a5eb2cc4d2c8cd0592932bbcfbdb2d18b29455d3d08203fb683585ec7acf9acf17c299a6b86fe6110e96f91aea8ccceddc4c247e9e0ab37a5d016904457822212f7353461b50f56cb6e9afbdb089203f2f242ceb6241a03dd4865e020a93a6a261d9ee39ebd9a5f79d9f90d14a1d9d671b1ead744228e056155de6c66c56b08364b1d8706f1cc1b3b664c288500af3cdc650ac7c607b6434218136d16ac5c3c75923328481f9288a53b393533d8404a27efe0a8c6f6a9933c488"),
	//	}
	//	TestOperator6Proof10Operators = spec.SignedProof{
	//		Proof: &spec.Proof{
	//			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
	//			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsShare6),
	//			SharePubKey:     ShareSK(TestValidator10OperatorsShare6).GetPublicKey().Serialize(),
	//			Owner:           TestOwnerAddress,
	//		},
	//		Signature: DecodeHexNoError("5f375203a0b36868088707a589e250961e6e21ab8ecd68171287bf0fa11514b64401f3f0565fe1539bf98c741e363668ba2f2fd2b07ff091f9995d075ec05081ecf5c68e37f3a5eb2cc4d2c8cd0592932bbcfbdb2d18b29455d3d08203fb683585ec7acf9acf17c299a6b86fe6110e96f91aea8ccceddc4c247e9e0ab37a5d016904457822212f7353461b50f56cb6e9afbdb089203f2f242ceb6241a03dd4865e020a93a6a261d9ee39ebd9a5f79d9f90d14a1d9d671b1ead744228e056155de6c66c56b08364b1d8706f1cc1b3b664c288500af3cdc650ac7c607b6434218136d16ac5c3c75923328481f9288a53b393533d8404a27efe0a8c6f6a9933c488"),
	//	}
	//	TestOperator7Proof10Operators = spec.SignedProof{
	//		Proof: &spec.Proof{
	//			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
	//			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsShare7),
	//			SharePubKey:     ShareSK(TestValidator10OperatorsShare7).GetPublicKey().Serialize(),
	//			Owner:           TestOwnerAddress,
	//		},
	//		Signature: DecodeHexNoError("5f375203a0b36868088707a589e250961e6e21ab8ecd68171287bf0fa11514b64401f3f0565fe1539bf98c741e363668ba2f2fd2b07ff091f9995d075ec05081ecf5c68e37f3a5eb2cc4d2c8cd0592932bbcfbdb2d18b29455d3d08203fb683585ec7acf9acf17c299a6b86fe6110e96f91aea8ccceddc4c247e9e0ab37a5d016904457822212f7353461b50f56cb6e9afbdb089203f2f242ceb6241a03dd4865e020a93a6a261d9ee39ebd9a5f79d9f90d14a1d9d671b1ead744228e056155de6c66c56b08364b1d8706f1cc1b3b664c288500af3cdc650ac7c607b6434218136d16ac5c3c75923328481f9288a53b393533d8404a27efe0a8c6f6a9933c488"),
	//	}
	//	TestOperator8Proof10Operators = spec.SignedProof{
	//		Proof: &spec.Proof{
	//			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
	//			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsShare8),
	//			SharePubKey:     ShareSK(TestValidator10OperatorsShare8).GetPublicKey().Serialize(),
	//			Owner:           TestOwnerAddress,
	//		},
	//		Signature: DecodeHexNoError("5f375203a0b36868088707a589e250961e6e21ab8ecd68171287bf0fa11514b64401f3f0565fe1539bf98c741e363668ba2f2fd2b07ff091f9995d075ec05081ecf5c68e37f3a5eb2cc4d2c8cd0592932bbcfbdb2d18b29455d3d08203fb683585ec7acf9acf17c299a6b86fe6110e96f91aea8ccceddc4c247e9e0ab37a5d016904457822212f7353461b50f56cb6e9afbdb089203f2f242ceb6241a03dd4865e020a93a6a261d9ee39ebd9a5f79d9f90d14a1d9d671b1ead744228e056155de6c66c56b08364b1d8706f1cc1b3b664c288500af3cdc650ac7c607b6434218136d16ac5c3c75923328481f9288a53b393533d8404a27efe0a8c6f6a9933c488"),
	//	}
	//	TestOperator9Proof10Operators = spec.SignedProof{
	//		Proof: &spec.Proof{
	//			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
	//			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsShare9),
	//			SharePubKey:     ShareSK(TestValidator10OperatorsShare9).GetPublicKey().Serialize(),
	//			Owner:           TestOwnerAddress,
	//		},
	//		Signature: DecodeHexNoError("5f375203a0b36868088707a589e250961e6e21ab8ecd68171287bf0fa11514b64401f3f0565fe1539bf98c741e363668ba2f2fd2b07ff091f9995d075ec05081ecf5c68e37f3a5eb2cc4d2c8cd0592932bbcfbdb2d18b29455d3d08203fb683585ec7acf9acf17c299a6b86fe6110e96f91aea8ccceddc4c247e9e0ab37a5d016904457822212f7353461b50f56cb6e9afbdb089203f2f242ceb6241a03dd4865e020a93a6a261d9ee39ebd9a5f79d9f90d14a1d9d671b1ead744228e056155de6c66c56b08364b1d8706f1cc1b3b664c288500af3cdc650ac7c607b6434218136d16ac5c3c75923328481f9288a53b393533d8404a27efe0a8c6f6a9933c488"),
	//	}
	//	TestOperator10Proof10Operators = spec.SignedProof{
	//		Proof: &spec.Proof{
	//			ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
	//			EncryptedShare:  DecodeHexNoError(TestValidator10OperatorsShare10),
	//			SharePubKey:     ShareSK(TestValidator10OperatorsShare10).GetPublicKey().Serialize(),
	//			Owner:           TestOwnerAddress,
	//		},
	//		Signature: DecodeHexNoError("5f375203a0b36868088707a589e250961e6e21ab8ecd68171287bf0fa11514b64401f3f0565fe1539bf98c741e363668ba2f2fd2b07ff091f9995d075ec05081ecf5c68e37f3a5eb2cc4d2c8cd0592932bbcfbdb2d18b29455d3d08203fb683585ec7acf9acf17c299a6b86fe6110e96f91aea8ccceddc4c247e9e0ab37a5d016904457822212f7353461b50f56cb6e9afbdb089203f2f242ceb6241a03dd4865e020a93a6a261d9ee39ebd9a5f79d9f90d14a1d9d671b1ead744228e056155de6c66c56b08364b1d8706f1cc1b3b664c288500af3cdc650ac7c607b6434218136d16ac5c3c75923328481f9288a53b393533d8404a27efe0a8c6f6a9933c488"),
	//	}
)

var (
	TestOperator1Proof13Operators = spec.SignedProof{
		Proof: &spec.Proof{
			ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
			EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare1),
			SharePubKey:     ShareSK(TestValidator13OperatorsShare1).GetPublicKey().Serialize(),
			Owner:           TestOwnerAddress,
		},
		Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	}
	//TestOperator2Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare2),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare2).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
	//TestOperator3Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare3),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare3).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
	//TestOperator4Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare4),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare4).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
	//TestOperator5Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare5),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare5).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
	//TestOperator6Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare6),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare6).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
	//TestOperator7Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare7),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare7).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
	//TestOperator8Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare8),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare8).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
	//TestOperator9Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare9),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare9).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
	//TestOperator10Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare10),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare10).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
	//TestOperator11Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare11),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare11).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
	//TestOperator12Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare12),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare12).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
	//TestOperator13Proof13Operators = spec.SignedProof{
	//	Proof: &spec.Proof{
	//		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
	//		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare13),
	//		SharePubKey:     ShareSK(TestValidator13OperatorsShare13).GetPublicKey().Serialize(),
	//		Owner:           TestOwnerAddress,
	//	},
	//	Signature: DecodeHexNoError("760e50c1ddf922a738be9adee7029733c6811db460933e7bc4d55ff26c512af761922880f4fb13b5e64eeaaa8ffe578e62c00a4d8a901b031d8bd20ab525319e1fb45ac620815db0d41c10532cca5120a793128641797eef082342c2ebe9f4d82fb1afbca27b9b42f175c17ccbe24ca80a7b7cd2565a86776ddba3dc4567fec7a2f24fae6a7fa34a0e7bc0d4028587870e60727a92c3c19083d3cbab73e615906d4af210d7d8e7c22065603dbd0e3f98bfa7762040aea4a5dcf832169262c0fc2864ab86f0b361db803812908d454ec65b4da8266f3ebd229d71469a7c6bc7d672c196b8787602c5ba04624b229ec764157d94ddafa1b6227da01cc6b69446f1"),
	//}
)
