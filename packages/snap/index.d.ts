declare interface Window {
  ethereum: any;
}

declare module '*.wasm' {
  const content: any;
  export default content;
}
