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
      triggerResult: false,
      mockValue: ""
    };
    
    this.validateCertificate = this.validateCertificate.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser,
      triggerResult: false,
      mockValue: ""
    });
  }
  
  validateCertificate(e) {
    e.preventDefault();
		var scheme = {
      scheme_type: this.state.scheme.scheme_type,
      scheme_name: this.state.scheme.scheme_name,
      username: this.state.currentUser.username,
			value: {
			}
		};
    
    apiManager.glewlwydRequest("/auth/", "POST", scheme)
    .then(() => {
      messageDispatcher.sendMessage('App', {type: 'loginSuccess', loginSuccess: true});
    })
    .fail(() => {
      messageDispatcher.sendMessage('Notification', {type: "danger", message: i18next.t("login.error-certificate-value")});
    });
  }
  
  render() {
    return (
      <form action="#" id="certificateSchemeForm">
        <div className="form-group">
          <h5>{i18next.t("login.certificate-scheme-title")}</h5>
        </div>
        <button type="button" name="certificatebut" id="certificatebut" className="btn btn-primary" onClick={(e) => this.validateCertificate(e)} title={i18next.t("login.certificate-login-authenticate")}>{i18next.t("login.certificate-login-authenticate")}</button>
      </form>
    );
  }
}

export default CertificateSchemeForm;
