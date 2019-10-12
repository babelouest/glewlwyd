import React, { Component } from 'react';
import i18next from 'i18next';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import SchemeAuthForm from './SchemeAuthForm';

class SchemeAuth extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      scheme: props.scheme,
      schemeListRequired: props.schemeListRequired,
      client: props.client,
      currentUser: props.currentUser,
      canContinue: !props.scheme,
      show: props.show
    };
    
    this.handleSelectScheme = this.handleSelectScheme.bind(this);
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      scheme: nextProps.scheme,
      schemeListRequired: nextProps.schemeListRequired,
      client: nextProps.client,
      currentUser: nextProps.currentUser,
      canContinue: !nextProps.scheme,
      show: nextProps.show
    });
  }
  
  handleSelectScheme(e, scheme) {
    e.preventDefault();
    this.setState({scheme: scheme});
  }

  render() {
    var iScope = 0;
    if (!this.state.canContinue) {
      var schemeForm = "";
      var separator = "";
      var schemeList = [];
      if (this.state.scheme) {
        schemeForm = <SchemeAuthForm config={this.state.config} scheme={this.state.scheme} currentUser={this.state.currentUser}/>;
        separator = <div className="row">
            <div className="col-md-12">
              <hr/>
            </div>
          </div>;
      }
      if (this.state.schemeListRequired) {
        this.state.schemeListRequired.forEach((scheme, index) => {
          schemeList.push(
            <a className="dropdown-item" key={index} href="#" onClick={(e) => this.handleSelectScheme(e, scheme)}>{scheme.scheme_display_name}</a>
          );
        });
      }
      return (
        <div>
          {schemeForm}
          {separator}
          <div className="btn-group" role="group">
            <button className="btn btn-primary dropdown-toggle" type="button" id="selectScheme" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
              <i className="fas fa-user-lock btn-icon"></i>{i18next.t("login.login-choose-scheme")}
            </button>
            <div className="dropdown-menu" aria-labelledby="selectScheme">
              {schemeList}
            </div>
          </div>
        </div>
      );
    } else {
      var connectMessage;
      if (this.state.client) {
        connectMessage = i18next.t("login.connect-to", {client:this.state.client.name||this.state.client.client_id});
      } else {
        connectMessage = i18next.t("login.connection");
      }
      return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h3>{connectMessage}</h3>
          </div>
        </div>
        <hr/>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("login.wish-message")}</h4>
          </div>
        </div>
      </div>
      );
    }
  }
}

export default SchemeAuth;
