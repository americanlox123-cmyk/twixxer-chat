// public/rnnoise-worklet.js
// RNNoise AudioWorklet для реального шумоподавления в звонках TwixxerChat

class RNNoiseProcessor extends AudioWorkletProcessor {
  constructor() {
    super();
    this.rnnoise = null;
    this.buffer = new Float32Array(480); // RNNoise требует 480 сэмплов (10ms @ 48kHz)
    this.bufferIndex = 0;
    this.ready = false;
    this.port.onmessage = this.handleMessage.bind(this);
  }

  async handleMessage(event) {
    if (event.data.type === 'init') {
      try {
        // Динамический импорт WASM-модуля RNNoise
        const { default: initRnnoise, Rnnoise } = await import('@timephy/rnnoise-wasm');
        await initRnnoise(event.data.wasmPath);
        this.rnnoise = new Rnnoise();
        this.ready = true;
        this.port.postMessage({ type: 'ready' });
      } catch (e) {
        console.error('RNNoise init failed:', e);
        this.port.postMessage({ type: 'error', error: e.message });
      }
    }
  }

  process(inputs, outputs) {
    const input = inputs[0];
    const output = outputs[0];
    
    if (!input || !input[0] || !this.ready || !this.rnnoise) {
      // Пропускаем без обработки, если не готов
      if (input && input[0] && output && output[0]) {
        output[0].set(input[0]);
      }
      return true;
    }

    const inputChannel = input[0];
    const outputChannel = output[0];
    const frameSize = 480;

    for (let i = 0; i < inputChannel.length; i++) {
      this.buffer[this.bufferIndex++] = inputChannel[i];

      if (this.bufferIndex >= frameSize) {
        // Обработка через RNNoise
        const denoised = this.rnnoise.processFrame(this.buffer);
        
        // Записываем обработанные сэмплы в выход
        for (let j = 0; j < frameSize; j++) {
          if (i - frameSize + 1 + j >= 0 && i - frameSize + 1 + j < outputChannel.length) {
            outputChannel[i - frameSize + 1 + j] = denoised[j];
          }
        }
        
        this.bufferIndex = 0;
      }
    }

    // Дописываем остаток, если буфер не заполнился
    if (this.bufferIndex > 0 && this.bufferIndex < frameSize) {
      for (let k = 0; k < this.bufferIndex; k++) {
        const idx = inputChannel.length - this.bufferIndex + k;
        if (idx >= 0 && idx < outputChannel.length) {
          outputChannel[idx] = this.buffer[k];
        }
      }
    }

    return true;
  }
}

registerProcessor('rnnoise-processor', RNNoiseProcessor);