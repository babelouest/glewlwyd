import React, { Component } from 'react';
import i18next from 'i18next';

class ErrorConfig extends Component {
  constructor(props) {
    super(props);
  }
  
  render() {
    return (
      <div className="alert alert-danger perfect-centering" role="alert">
        {i18next.t("error-config")}
      </div>
    );
  }
}

export default ErrorConfig;
