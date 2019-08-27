import React, { Component } from 'react';

import apiManager from '../../lib/APIManager';
import messageDispatcher from '../../lib/MessageDispatcher';

class CertificateSchemeForm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scheme: props.scheme,
      currentUser: props.currentUser,
      authResult: false
    };
    
    this.validateCertificate = this.validateCertificate.bind(this);
    
    this.validateCertificate();
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser,
      authResult: false
    }, () => {
      this.validateCertificate();
    });
  }
  
  validateCertificate() {
		var scheme = {
      scheme_type: this.state.scheme.scheme_type,
      scheme_name: this.state.scheme.scheme_name,
      username: this.state.currentUser.username,
			value: {
			}
		};
    
    apiManager.glewlwydRequest("/auth/", "POST", scheme)
    .then(() => {
      this.setState({authResult: true}, () => {
        messageDispatcher.sendMessage('App', {type: 'loginSuccess', loginSuccess: true});
      });
    })
    .fail(() => {
      this.setState({authResult: false});
    });
  }
  
  render() {
    var authResult;
    if (this.state.authResult) {
      authResult = <div className="alert alert-success" role="alert">{i18next.t("login.certificate-scheme-auth-success")}</div>;
    } else {
      authResult = <div className="alert alert-danger" role="alert">{i18next.t("login.certificate-scheme-auth-invalid")}</div>;
    }
    return (
      <form action="#" id="certificateSchemeForm">
        <div className="form-group">
          <h5>{i18next.t("login.certificate-scheme-title")}</h5>
        </div>
        <div className="form-group">
          {authResult}
        </div>
      </form>
    );
  }
}

export default CertificateSchemeForm;
