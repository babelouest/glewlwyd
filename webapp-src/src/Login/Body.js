import React, { Component } from 'react';
import i18next from 'i18next';

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
      schemeListRequired: props.schemeListRequired,
      showGrant: props.showGrant,
      infoSomeScopeUnavailable: props.infoSomeScopeUnavailable
    };
    
    messageDispatcher.subscribe('Body', (message) => {
    });
  }
  
  componentWillReceiveProps(nextProps) {
    this.setState({
      config: nextProps.config,
      currentUser: nextProps.currentUser,
      client: nextProps.client,
      scope: nextProps.scope,
      scheme: nextProps.scheme,
      schemeListRequired: nextProps.schemeListRequired,
      showGrant: nextProps.showGrant,
      infoSomeScopeUnavailable: nextProps.infoSomeScopeUnavailable
    });
  }

	render() {
    var content, profilePicture;
    if (this.state.showGrant) {
      content = <div id="carouselBody" className="carousel slide" data-ride="carousel">
        <div className="carousel-inner">
          <div className={"carousel-item" + (this.state.showGrant?" active":"")}>
            <GrantScope config={this.state.config} currentUser={this.state.currentUser} client={this.state.client} scope={this.state.scope} infoSomeScopeUnavailable={this.state.infoSomeScopeUnavailable} />
          </div>
        </div>
      </div>;
    } else {
      content = <div className="row">
        <div className="col-md-12">
          <SchemeAuth config={this.state.config} currentUser={this.state.currentUser} scheme={this.state.scheme} schemeListRequired={this.state.schemeListRequired} client={this.state.client} />
        </div>
      </div>
    }
    if (this.state.config.profilePicture && this.state.currentUser[this.state.config.profilePicture.property]) {
      var picData = this.state.currentUser[this.state.config.profilePicture.property];
      if (Array.isArray(picData)) {
        picData = picData[0];
      }
      profilePicture = 
        <div className="row">
          <div className="col-md-12 text-center">
            <img className="btn-icon-right img-medium" src={"data:"+this.state.config.profilePicture.type+";base64,"+picData} alt={this.state.config.profilePicture.property} />
          </div>
        </div>
    }
		return (
      <div>
        {profilePicture}
        <div className="row">
          <div className="col-md-12 text-center">
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
