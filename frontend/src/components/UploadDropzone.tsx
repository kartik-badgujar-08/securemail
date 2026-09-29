import React, { useState, useRef } from "react";
import { UploadCloud, AlertTriangle, Loader2 } from "lucide-react";
import { api } from "../services/api";
import type { UploadResponse } from "../services/api";

interface UploadDropzoneProps {
  onUploadSuccess: (response: UploadResponse) => void;
  isProcessing: boolean;
}

export const UploadDropzone: React.FC<UploadDropzoneProps> = ({
  onUploadSuccess,
  isProcessing,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const validateAndUpload = async (file: File) => {
    setError(null);
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (!ext || !["pcap", "pcapng", "cap"].includes(ext)) {
      setError("Invalid file type. Only .pcap, .pcapng, and .cap files are permitted.");
      return;
    }

    if (file.size > 100 * 1024 * 1024) {
      setError("File exceeds 100 MB limit.");
      return;
    }

    setSelectedFile(file);
    setUploading(true);

    try {
      const res = await api.uploadPCAP(file, true);
      onUploadSuccess(res);
    } catch (err: any) {
      setError(err.message || "Upload failed. Please check connection to backend.");
    } finally {
      setUploading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndUpload(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      validateAndUpload(e.target.files[0]);
    }
  };

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">
          <UploadCloud size={18} />
          PCAP Capture Ingestion
        </h2>
        <span className="badge badge-neutral">Max: 100 MB</span>
      </div>

      <div className="card-body">
        {error && (
          <div className="alert alert-danger" role="alert">
            <AlertTriangle size={18} style={{ flexShrink: 0, marginTop: "2px" }} />
            <div>
              <strong>Upload Error:</strong> {error}
            </div>
          </div>
        )}

        <div
          className={`dropzone ${dragActive ? "active" : ""}`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
          onClick={() => inputRef.current?.click()}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".pcap,.pcapng,.cap"
            style={{ display: "none" }}
            onChange={handleChange}
            disabled={uploading || isProcessing}
          />

          {uploading || isProcessing ? (
            <div>
              <Loader2 size={36} className="dropzone-icon" style={{ animation: "spin 1s linear infinite" }} />
              <div className="dropzone-title">
                {uploading ? "Uploading Capture..." : "Analyzing PCAP & Reassembling Streams..."}
              </div>
              <div className="dropzone-subtitle font-mono">
                {selectedFile ? `${selectedFile.name} (${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB)` : ""}
              </div>
            </div>
          ) : (
            <div>
              <UploadCloud size={38} className="dropzone-icon" />
              <div className="dropzone-title">Drag & drop PCAP capture file here, or click to browse</div>
              <div className="dropzone-subtitle">
                Passively analyzes SMTP (25/587), IMAP (143/993), and POP3 (110/995) sessions
              </div>
              <div className="file-specs">
                <span>Formats: <strong>.pcap, .pcapng, .cap</strong></span>
                <span>•</span>
                <span>Engine: <strong>TShark / Scapy</strong></span>
                <span>•</span>
                <span>Limit: <strong>100 MB</strong></span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
