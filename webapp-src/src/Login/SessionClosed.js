import React, { Component } from 'react';
import i18next from 'i18next';

import messageDispatcher from '../lib/MessageDispatcher';

class SessionClosed extends Component {
  constructor(props) {
    super(props);
    
    this.state = {
      config: props.config
    };
  }
  
  login() {
    messageDispatcher.sendMessage('App', {type: 'SessionReopen'});
  }
  
  render() {
    return (
    <div>
      <div className="row">
        <div className="col-md-12 text-center">
          <h3>{i18next.t("login.session-closed-title")}</h3>
        </div>
      </div>
      <hr/>
      <div className="row">
        <div className="col-md-12 text-center">
          <h4>{i18next.t("login.session-closed-message")}</h4>
        </div>
      </div>
      <hr/>
      <div className="row">
        <div className="col-md-12 text-center">
          <button type="button" className="btn btn-primary" onClick={this.login}>
            {i18next.t("title-login")}
          </button>
        </div>
      </div>
    </div>);
  }
}

export default SessionClosed;
