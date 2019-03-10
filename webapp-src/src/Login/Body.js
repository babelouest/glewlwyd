import React, { Component } from 'react';

import apiManager from '../lib/APIManager';
import messageDispatcher from '../lib/MessageDispatcher';
import GrantScope from './GrantScope';
import SchemeAuth from './SchemeAuth';

class Body extends Component {
  constructor(props) {
    super(props);

    this.state = {
      config: props.config,
      currentUser: props.currentUser,
      client: props.client,
      scope: props.scope,
      scheme: props.scheme,
      showGrant: false
    };
    
    messageDispatcher.subscribe('Body', (message) => {
      if (message === 'GrantScope') {
        this.setState({showGrant: !this.state.showGrant});
      }
    });
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      currentUser: nextProps.currentUser,
      client: nextProps.client,
      scope: nextProps.scope,
      scheme: nextProps.scheme,
      showGrant: false
    });
  }

	render() {
    var content = "";
    if (this.state.showGrant) {
      content = <GrantScope config={this.state.config} currentUser={this.state.currentUser} client={this.state.client} scope={this.state.scope}/>
    } else {
      content = <SchemeAuth config={this.state.config} scheme={this.state.scheme} currentUser={this.state.currentUser} client={this.state.client}/>
    }
		return (
      <div>
        <div className="row">
          <div className="col-md-12">
            <h4>{i18next.t("login.hello", {name: (this.state.currentUser.name || this.state.currentUser.username)})}</h4>
          </div>
        </div>
        <div className="row">
          <div className="col-md-12">
            <hr/>
          </div>
        </div>
        {content}
      </div>
		);
	}
}

export default Body;
