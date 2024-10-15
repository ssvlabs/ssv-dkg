import { useState } from "react";
import { hashMessage as performMessageHash } from 'viem'
import {
  MetaMaskButton,
  useAccount,
  useSDK,
  useSignMessage,
} from "@metamask/sdk-react-ui";
import "./App.css";

function AppReady() {
  const [messageToSign, setMessageToSign] = useState("");
  const {
    data: signData,
    isError: isSignError,
    isLoading: isSignLoading,
    isSuccess: isSignSuccess,
    signMessage,
  } = useSignMessage({
    message: performMessageHash(messageToSign),
  });
  const { isConnected } = useAccount();
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
            <form>
              <input
                value={messageToSign}
                onChange={(e) => setMessageToSign(e.target.value)}
              />
            </form>
            <div style={{ marginTop: 20 }}>
              <button disabled={isSignLoading} onClick={(msg) => signMessage()}>
                Sign message
              </button>
              {isSignSuccess && <div>Signature: {signData}</div>}
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
