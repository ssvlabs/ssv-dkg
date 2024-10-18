import { useState, useRef } from "react";
import {
  stripHexPrefix,
  fromRpcSig,
  setLengthLeft,
  toRpcSig,
} from "@ethereumjs/util";
import {
  MetaMaskButton,
  useAccount,
  useSDK,
  useSignMessage,
} from "@metamask/sdk-react-ui";
import "./App.css";

function AppReady() {
  const [messageToSign, setMessageToSign] = useState("reshare/resign msg here");
  const [copySuccess, setCopySuccess] = useState("");
  const textAreaRef = useRef(null);

  const {
    data: signData,
    isError: isSignError,
    isLoading: isSignLoading,
    isSuccess: isSignSuccess,
    signMessage,
  } = useSignMessage({
    message: stripHexPrefix(messageToSign),
  });
  const { isConnected } = useAccount();
  const processSig = (signData) => {
    const sigParams = fromRpcSig(signData);
    const sig = toRpcSig(sigParams.v - 27n, sigParams.r, sigParams.s);
    return stripHexPrefix(sig);
  };
  function copyToClipboard(e) {
    textAreaRef.current.select();
    document.execCommand("copy");
    e.target.focus();
    setCopySuccess("Copied!");
  }
  return (
    <div className="App">
      <header className="App-header">
        <span>
          {/* TODO: Remove once we fix this issue */}
          <p>This is example to sign reshare/resign message hash.</p>
        </span>
        <MetaMaskButton theme={"light"} color="white"></MetaMaskButton>
        {isConnected && (
          <>
            <form style={{ marginTop: 20 }}>
              <div style={{ marginBottom: 20 }}>Please enter msg to sign</div>
              <textarea
                style={{
                  padding: "10px 20px",
                  textAlign: "center",
                  maxWidth: "100%",
                  minWidth: "60%",
                  width: "600px",
                  height: '20px',
                  margin: "0 auto",
                }}
                value={messageToSign}
                onChange={(e) => setMessageToSign(e.target.value)}
              />
            </form>
            <div style={{ marginTop: 20 }}>
              <button disabled={isSignLoading} onClick={(msg) => signMessage()}>
                Sign message
              </button>
              {isSignSuccess && (
                <div>
                  <h4>Signature:</h4>

                  <div>
                    <form>
                      <textarea
                        ref={textAreaRef}
                        value={processSig(signData)}
                        style={{
                          padding: "10px 20px",
                          textAlign: "center",
                          maxWidth: "80%",
                          minWidth: "60%",
                          width: "600px",
                          margin: "0 auto",
                        }}
                      />
                    </form>
                    {
                      /* Logical shortcut for only displaying the 
          button if the copy command exists */
                      document.queryCommandSupported("copy") && (
                        <div>
                          <button onClick={copyToClipboard}>Copy</button>
                          {copySuccess}
                        </div>
                      )
                    }
                  </div>
                </div>
              )}
              {isSignError && <div>Error signing message</div>}
            </div>
          </>
        )}
      </header>
    </div>
  );
}

function App() {
  const { ready } = useSDK();

  if (!ready) {
    return <div>Loading...</div>;
  }

  return <AppReady />;
}

export default App;
