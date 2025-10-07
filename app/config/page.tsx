"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Settings, Save, Eye, EyeOff, Shield, Brain, Lock } from "lucide-react";
import { Header } from "@/components/layout/header";
import { TerminalBox } from "@/components/layout/terminal-box";

export default function ConfigPage() {
  const [apiKey, setApiKey] = useState("");
  const [showApiKey, setShowApiKey] = useState(false);
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [aiProvider, setAiProvider] = useState("gemini");
  const [confidenceThreshold, setConfidenceThreshold] = useState(0.7);
  const [enableAI, setEnableAI] = useState(false);
  const [keyStatus, setKeyStatus] = useState<"none" | "valid" | "invalid">("none");
  const [statusMessage, setStatusMessage] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  const bufferToBase64 = (buffer: ArrayBuffer | Uint8Array) => {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  };

  const deriveEncryptionKey = async (secret: string, salt: ArrayBuffer) => {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "PBKDF2" },
      false,
      ["deriveKey"],
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100_000,
        hash: "SHA-256",
      },
      keyMaterial,
      {
        name: "AES-GCM",
        length: 256,
      },
      false,
      ["encrypt", "decrypt"],
    );
  };

  const handleSaveConfig = async () => {
    if (typeof window === "undefined" || !window.crypto?.subtle) {
      setStatusMessage({ type: "error", message: "Secure context required. Please use a modern browser over HTTPS." });
      return;
    }

    const trimmedKey = apiKey.trim();
    const trimmedPassphrase = passphrase.trim();

    if (trimmedKey.length < 16) {
      setKeyStatus("invalid");
      setStatusMessage({ type: "error", message: "API keys usually contain at least 16 characters. Double-check and try again." });
      return;
    }

    if (trimmedPassphrase.length < 8) {
      setKeyStatus("invalid");
      setStatusMessage({ type: "error", message: "Choose a passphrase with at least 8 characters to encrypt the key." });
      return;
    }

    try {
      setIsSaving(true);
      setStatusMessage(null);
      const encoder = new TextEncoder();
      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const cryptoKey = await deriveEncryptionKey(trimmedPassphrase, saltBytes.buffer.slice(0));
      const cipherBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        encoder.encode(trimmedKey),
      );

      const payload = {
        salt: bufferToBase64(saltBytes),
        iv: bufferToBase64(iv),
        cipher: bufferToBase64(new Uint8Array(cipherBuffer)),
        provider: aiProvider,
        confidence: confidenceThreshold,
        enableAI,
        storedAt: new Date().toISOString(),
      };

      sessionStorage.setItem("secure_ai_config", JSON.stringify(payload));
      setKeyStatus("valid");
      setStatusMessage({ type: "success", message: "Encrypted configuration stored for this session. Keep your passphrase safe." });
      setApiKey("");
    } catch (error) {
      console.error("Failed to encrypt API key", error);
      setKeyStatus("invalid");
      setStatusMessage({ type: "error", message: "We could not secure the key. Try a different passphrase or refresh the page." });
    } finally {
      setIsSaving(false);
    }
  };

  const handleClearKey = () => {
    setApiKey("");
    setPassphrase("");
    setKeyStatus("none");
    setStatusMessage(null);
    sessionStorage.removeItem("secure_ai_config");
  };

  return (
    <>
      <Header />
      <main className="relative mx-auto max-w-7xl px-4 py-8 text-foreground">
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-12 text-center"
        >
          <h1 className="mb-4 flex items-center justify-center gap-3 text-4xl font-semibold">
            <Settings className="h-10 w-10 text-brand" />
            API Configuration
          </h1>
          <p className="text-lg text-muted-foreground">
            Configure AI API settings for enhanced vulnerability analysis
          </p>
        </motion.div>

        <div className="space-y-8">
          {/* Security Notice */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
          >
            <div className="mb-6 rounded-xl border border-brand/30 bg-brand/10 p-4">
              <div className="flex items-start gap-3">
                <Shield className="mt-0.5 h-5 w-5 text-brand" />
                <div>
                  <h3 className="mb-1 font-semibold text-brand">Security Notice</h3>
                  <p className="text-sm text-muted-foreground">
                    API keys are encrypted with your passphrase and kept only in session memory. Nothing is written to disk or
                    transmitted to our servers. Closing the tab clears the encrypted bundle automatically.
                  </p>
                </div>
              </div>
            </div>
          </motion.div>

          {/* AI Configuration */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
          >
            <TerminalBox title="AI Model Configuration">
              <div className="space-y-6">
                <div className="grid gap-6 lg:grid-cols-2">
                  <div className="space-y-4">
                    <label className="block text-sm">
                      <span className="mb-2 block font-medium text-foreground">AI Provider</span>
                      <select
                        className="w-full rounded border border-border bg-card px-3 py-2 text-foreground shadow-sm focus:outline-none focus:ring-2 focus:ring-brand"
                        value={aiProvider}
                        onChange={(e) => setAiProvider(e.target.value)}
                      >
                        <option value="gemini">Google Gemini (Recommended)</option>
                        <option value="openai">OpenAI GPT-4</option>
                        <option value="anthropic">Anthropic Claude</option>
                      </select>
                      <span className="mt-1 block text-xs text-muted-foreground">
                        Select your preferred AI model for code analysis
                      </span>
                    </label>

                    <label className="block text-sm">
                      <span className="mb-2 block font-medium text-foreground">
                        Analysis Confidence: {confidenceThreshold}
                      </span>
                      <input 
                        className="w-full rounded border border-border bg-card px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-brand" 
                        type="range"
                        min="0.3"
                        max="0.9"
                        step="0.1"
                        value={confidenceThreshold}
                        onChange={(e) => setConfidenceThreshold(parseFloat(e.target.value))}
                      />
                      <span className="mt-1 block text-xs text-muted-foreground">
                        Higher values = fewer false positives, lower values = more thorough analysis
                      </span>
                    </label>
                  </div>

                  <div className="space-y-4">
                    <label className="block text-sm">
                      <span className="mb-2 block font-medium text-foreground">API Key</span>
                      <div className="relative">
                        <input
                          className="w-full rounded border border-border bg-card px-3 py-2 pr-10 text-foreground focus:outline-none focus:ring-2 focus:ring-brand"
                          type={showApiKey ? "text" : "password"}
                          placeholder="Enter your API key"
                          value={apiKey}
                          onChange={(e) => setApiKey(e.target.value)}
                        />
                        <button
                          type="button"
                          onClick={() => setShowApiKey(!showApiKey)}
                          className="absolute right-3 top-1/2 -translate-y-1/2 transform text-muted-foreground transition-colors hover:text-foreground"
                        >
                          {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>
                      {keyStatus === "valid" && (
                        <span className="mt-1 block text-xs text-emerald-600">✓ Encrypted API key stored for this session</span>
                      )}
                      {keyStatus === "invalid" && (
                        <span className="mt-1 block text-xs text-red-600">✗ We could not validate the key or passphrase. Check both and try again.</span>
                      )}
                    </label>

                    <label className="block text-sm">
                      <span className="mb-2 block font-medium text-foreground">Encryption Passphrase</span>
                      <div className="relative">
                        <input
                          className="w-full rounded border border-border bg-card px-3 py-2 pr-10 text-foreground focus:outline-none focus:ring-2 focus:ring-brand"
                          type={showPassphrase ? "text" : "password"}
                          placeholder="Create a passphrase (min 8 characters)"
                          value={passphrase}
                          onChange={(e) => setPassphrase(e.target.value)}
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassphrase(!showPassphrase)}
                          className="absolute right-3 top-1/2 -translate-y-1/2 transform text-muted-foreground transition-colors hover:text-foreground"
                        >
                          {showPassphrase ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>
                      <span className="mt-1 block text-xs text-muted-foreground">
                        This never leaves your browser. You’ll need it to decrypt the key when triggering AI analysis.
                      </span>
                    </label>

                    <div className="flex items-center gap-3 rounded-lg border border-border bg-card p-4 shadow-sm">
                      <div className="flex items-center">
                        <input
                          type="checkbox"
                          id="enableAI"
                          checked={enableAI}
                          onChange={(e) => setEnableAI(e.target.checked)}
                          className="h-4 w-4 rounded border-border text-brand focus:ring-brand"
                        />
                        <label htmlFor="enableAI" className="ml-2 text-sm font-medium text-foreground">
                          Enable AI Analysis
                        </label>
                      </div>
                      <Brain className="h-5 w-5 text-brand" />
                    </div>
                  </div>
                </div>

                <div className="border-t border-border pt-6">
                  <div className="flex justify-center gap-4">
                    <motion.button
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                      onClick={handleSaveConfig}
                      disabled={isSaving}
                      className="flex items-center gap-3 rounded-lg bg-brand px-6 py-3 font-semibold text-white transition-colors hover:bg-brand/90 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      <Save className="h-5 w-5" />
                      {isSaving ? "Encrypting..." : "Save Configuration"}
                    </motion.button>
                    
                    <motion.button
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                      onClick={handleClearKey}
                      className="flex items-center gap-3 rounded-lg bg-red-500 px-6 py-3 font-semibold text-white transition-colors hover:bg-red-400"
                    >
                      <Lock className="h-5 w-5" />
                      Clear Session
                    </motion.button>
                  </div>
                  {statusMessage && (
                    <div
                      className={`mt-6 rounded-lg border px-4 py-3 text-sm ${
                        statusMessage.type === "success"
                          ? "border-[#355952] bg-[#355952]/10 text-[#355952]"
                          : "border-[#E37769] bg-[#E37769]/10 text-[#355952]"
                      }`}
                    >
                      {statusMessage.message}
                    </div>
                  )}
                </div>
              </div>
            </TerminalBox>
          </motion.div>

          {/* Usage Guide */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <TerminalBox title="How to Get API Keys">
              <div className="grid gap-6 md:grid-cols-3">
                <div className="text-center">
                  <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-lg border border-[#355952]/30 bg-[#355952]/10 text-[#355952]">
                    <span className="font-bold">G</span>
                  </div>
                  <h3 className="mb-2 font-semibold text-foreground">Google Gemini</h3>
                  <p className="mb-3 text-sm text-muted-foreground">Free tier available</p>
                  <a href="https://makersuite.google.com/" target="_blank" rel="noopener noreferrer" 
                     className="text-sm font-medium text-brand transition-colors hover:text-brand/80">
                    Get Gemini API Key →
                  </a>
                </div>
                
                <div className="text-center">
                  <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-lg border border-[#E37769]/30 bg-[#E37769]/10 text-[#E37769]">
                    <span className="font-bold">O</span>
                  </div>
                  <h3 className="mb-2 font-semibold text-foreground">OpenAI</h3>
                  <p className="mb-3 text-sm text-muted-foreground">Pay-per-use model</p>
                  <a href="https://platform.openai.com/" target="_blank" rel="noopener noreferrer" 
                     className="text-sm font-medium text-brand transition-colors hover:text-brand/80">
                    Get OpenAI API Key →
                  </a>
                </div>
                
                <div className="text-center">
                  <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-lg border border-[#355952]/40 bg-[#355952]/15 text-[#355952]">
                    <span className="font-bold">C</span>
                  </div>
                  <h3 className="mb-2 font-semibold text-foreground">Anthropic</h3>
                  <p className="mb-3 text-sm text-muted-foreground">Claude AI model</p>
                  <a href="https://console.anthropic.com/" target="_blank" rel="noopener noreferrer" 
                     className="text-sm font-medium text-brand transition-colors hover:text-brand/80">
                    Get Claude API Key →
                  </a>
                </div>
              </div>
            </TerminalBox>
          </motion.div>
        </div>
      </main>
    </>
  );
}
