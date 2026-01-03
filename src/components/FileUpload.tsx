import React, { useCallback, useState } from 'react';
import { Upload, FileText, AlertTriangle } from 'lucide-react';

interface FileUploadProps {
  onFileAnalyze: (content: string, filename: string) => void;
}

export default function FileUpload({ onFileAnalyze }: FileUploadProps) {
  const [dragActive, setDragActive] = useState(false);
  const [textInput, setTextInput] = useState('');

  const handleFile = useCallback((file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      onFileAnalyze(content, file.name);
    };
    reader.readAsText(file);
  }, [onFileAnalyze]);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    const files = Array.from(e.dataTransfer.files);
    const psFiles = files.filter(file => 
      file.name.endsWith('.ps1') || file.type === 'text/plain'
    );
    
    if (psFiles.length > 0) {
      handleFile(psFiles[0]);
    }
  }, [handleFile]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFile(file);
    }
  }, [handleFile]);

  const handleTextAnalysis = useCallback(() => {
    if (textInput.trim()) {
      onFileAnalyze(textInput, 'manual-input.ps1');
    }
  }, [textInput, onFileAnalyze]);

  return (
    <div className="space-y-6">
      {/* File Upload Area */}
      <div
        className={`relative border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
          dragActive
            ? 'border-blue-400 bg-blue-50 dark:bg-blue-950'
            : 'border-gray-300 dark:border-gray-600 hover:border-gray-400 dark:hover:border-gray-500'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <input
          type="file"
          accept=".ps1,.txt"
          onChange={handleFileInput}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
        />
        <div className="space-y-4">
          <Upload className="mx-auto h-12 w-12 text-gray-400" />
          <div>
            <p className="text-lg font-medium text-gray-900 dark:text-gray-100">
              Drop PowerShell files here
            </p>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              or click to browse (.ps1, .txt files)
            </p>
          </div>
        </div>
      </div>

      {/* Manual Text Input */}
      <div className="space-y-4">
        <div className="flex items-center space-x-2">
          <FileText className="h-5 w-5 text-gray-500" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-gray-100">
            Or paste PowerShell code
          </h3>
        </div>
        <textarea
          value={textInput}
          onChange={(e) => setTextInput(e.target.value)}
          placeholder="Paste your PowerShell script here..."
          className="w-full h-48 p-4 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 font-mono text-sm resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        />
        <button
          onClick={handleTextAnalysis}
          disabled={!textInput.trim()}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          Analyze Script
        </button>
      </div>

      {/* Security Warning */}
      <div className="flex items-start space-x-3 p-4 bg-amber-50 dark:bg-amber-950 border border-amber-200 dark:border-amber-800 rounded-lg">
        <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400 mt-0.5" />
        <div className="text-sm">
          <p className="font-medium text-amber-800 dark:text-amber-200">
            Security Notice
          </p>
          <p className="text-amber-700 dark:text-amber-300">
            This tool performs static analysis only. Scripts are never executed. 
            Always exercise caution when handling potentially malicious files.
          </p>
        </div>
      </div>
    </div>
  );
}