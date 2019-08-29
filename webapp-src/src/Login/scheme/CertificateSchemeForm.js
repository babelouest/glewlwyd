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
      authResult: -1
    };
    
    this.validateCertificate = this.validateCertificate.bind(this);
    
    this.validateCertificate();
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser
    }, () => {
      this.validateCertificate();
    });
  }
  
  validateCertificate() {
    if (this.state.authResult !== 1) {
      var scheme = {
        scheme_type: this.state.scheme.scheme_type,
        scheme_name: this.state.scheme.scheme_name,
        username: this.state.currentUser.username,
        value: {
        }
      };
      
      apiManager.glewlwydRequest("/auth/", "POST", scheme)
      .then(() => {
        this.setState({authResult: 1}, () => {
          messageDispatcher.sendMessage('App', {type: 'loginSuccess', loginSuccess: true});
        });
      })
      .fail(() => {
        this.setState({authResult: 0});
      });
    }
  }
  
  render() {
    var authResult;
    if (this.state.authResult === 1) {
      authResult = <div className="alert alert-success" role="alert">{i18next.t("login.certificate-scheme-auth-success")}</div>;
    } else if (this.state.authResult === 0) {
      authResult = 
      <div>
        <div className="alert alert-danger" role="alert">{i18next.t("login.certificate-scheme-auth-invalid")}</div>
        <button type="button" className="btn btn-primary" onClick={this.validateCertificate}>
          {i18next.t("login.certificate-login-authenticate")}
        </button>
      </div>
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
