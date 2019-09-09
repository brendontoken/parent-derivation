const path = require('path');

module.exports = {
  entry: './src/index.js',
  mode: 'development',
  output: {
    filename: 'pd.js',
    library: 'pd',
    path: path.resolve(__dirname, 'dist')
  },
  watch: true
};