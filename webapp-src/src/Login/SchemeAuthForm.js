import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';

import MockSchemeForm from './scheme/MockSchemeForm';
import EmailSchemeForm from './scheme/EmailSchemeForm';
import WebauthnForm from './scheme/WebauthnForm';
import OTPSchemeForm from './scheme/OTPSchemeForm';
import PasswordSchemeForm from './scheme/PasswordSchemeForm';
import CertificateSchemeForm from './scheme/CertificateSchemeForm';

class SchemeAuthForm extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scheme: props.scheme,
      currentUser: props.currentUser
    };
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      currentUser: nextProps.currentUser
    });
  }
  
  render() {
    if (this.state.scheme.scheme_type === "mock") {
      return (<MockSchemeForm config={this.state.config} scheme={this.state.scheme} currentUser={this.state.currentUser}/>);
    } else if (this.state.scheme.scheme_type === "email") {
      return (<EmailSchemeForm config={this.state.config} scheme={this.state.scheme} currentUser={this.state.currentUser}/>);
    } else if (this.state.scheme.scheme_type === "webauthn") {
      return (<WebauthnForm config={this.state.config} scheme={this.state.scheme} currentUser={this.state.currentUser}/>);
    } else if (this.state.scheme.scheme_type === "otp") {
      return (<OTPSchemeForm config={this.state.config} scheme={this.state.scheme} currentUser={this.state.currentUser}/>);
    } else if (this.state.scheme.scheme_type === "retype-password") {
      return (<PasswordSchemeForm config={this.state.config} scheme={this.state.scheme} currentUser={this.state.currentUser}/>);
    } else if (this.state.scheme.scheme_type === "certificate") {
      return (<CertificateSchemeForm config={this.state.config} scheme={this.state.scheme} currentUser={this.state.currentUser}/>);
    } else {
      return ("");
    }
  }
}

export default SchemeAuthForm;
