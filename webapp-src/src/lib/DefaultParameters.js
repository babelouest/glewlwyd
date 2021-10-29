class DefaultParameters {
  constructor() {
  }
  
  updateWithDefaultParameters(parameters, defaultParam) {
    Object.keys(defaultParam).forEach(key => {
      if (parameters[key] === undefined) {
        if (Object.isObject) {
          parameters[key] = Object.assign({}, defaultParam[key]);
        } else {
          parameters[key] = defaultParam[key]
        }
      }
    });
  }
}

let defaultParameters = new DefaultParameters();

export default defaultParameters;
