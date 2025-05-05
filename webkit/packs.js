class FireSensePackager {
  constructor() {
    this.files = new Map();
    this.chunkSize = 1024 * 1024; // 1MB chunks
  }

  /**
   * Add file to package
   * @param {string} name - Filename
   * @param {Blob|File} file - File content
   */
  async addFile(name, file) {
    const buffer = await file.arrayBuffer();
    this.files.set(name, {
      size: file.size,
      type: file.type,
      lastModified: file.lastModified,
      data: new Uint8Array(buffer)
    });
  }

  /**
   * Generate ZIP package
   * @returns {Promise<Blob>}
   */
  async generateZip() {
    const { default: JSZip } = await import('https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js');
    const zip = new JSZip();
    
    this.files.forEach((file, name) => {
      zip.file(name, file.data);
    });

    return zip.generateAsync({
      type: 'blob',
      compression: 'DEFLATE',
      compressionOptions: { level: 6 }
    });
  }

  /**
   * Compile files to single JS module
   * @returns {string} - JS module code
   */
  compileToJS() {
    let jsCode = `// FireSense Generated Bundle\nconst __FS_PACK = {\n`;
    
    this.files.forEach((file, name) => {
      jsCode += `  "${name}": {\n` +
                `    size: ${file.size},\n` +
                `    type: "${file.type}",\n` +
                `    lastModified: ${file.lastModified},\n` +
                `    data: new Uint8Array([${file.data.join(',')}])\n` +
                `  },\n`;
    });

    jsCode += `};\n\nexport default __FS_PACK;`;
    return jsCode;
  }

  /**
   * Process directory recursively
   * @param {FileSystemDirectoryHandle} dirHandle
   */
  async processDirectory(dirHandle, path = '') {
    for await (const [name, handle] of dirHandle.entries()) {
      const fullPath = `${path}/${name}`;
      
      if (handle.kind === 'file') {
        const file = await handle.getFile();
        await this.addFile(fullPath, file);
      } else if (handle.kind === 'directory') {
        await this.processDirectory(handle, fullPath);
      }
    }
  }
}

/*
const packager = new FireSensePackager();
const fileInput = document.getElementById('file-input');

fileInput.addEventListener('change', async (e) => {
  for (const file of e.target.files) {
    await packager.addFile(file.name, file);
  }
  
  // Get ZIP
  const zipBlob = await packager.generateZip();
  
  // Get JS Module
  const jsModule = packager.compileToJS();
  downloadFile('firesense-bundle.js', jsModule);
});

function downloadFile(filename, content) {
  const blob = new Blob([content], { type: 'application/javascript' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
}
*/
